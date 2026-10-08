import asyncio
import os
import tempfile
import unittest
from contextlib import closing
import sqlite3

from shadow_scan.database import Database
from shadow_scan.recon.dns import DnsRecord, dns_transitions, is_dangling, resolve_all
from shadow_scan.recon.models import ReconEvent, ScopeClass
from shadow_scan.recon.recon_db import ReconStore


class DnsTransitionTests(unittest.TestCase):
    LIVE = DnsRecord("h.example.com", status="resolves", a=("1.2.3.4",))
    DEAD = DnsRecord("h.example.com", status="nxdomain")

    def test_new_subdomain(self) -> None:
        self.assertEqual(dns_transitions(None, self.LIVE), [ReconEvent.NEW_SUBDOMAIN, ReconEvent.DNS_BECAME_LIVE])
        self.assertEqual(dns_transitions(None, self.DEAD), [ReconEvent.NEW_SUBDOMAIN])

    def test_became_live_and_dead(self) -> None:
        self.assertIn(ReconEvent.DNS_BECAME_LIVE, dns_transitions(self.DEAD, self.LIVE))
        self.assertIn(ReconEvent.DNS_BECAME_DEAD, dns_transitions(self.LIVE, self.DEAD))

    def test_ip_changed(self) -> None:
        new_ip = DnsRecord("h.example.com", status="resolves", a=("5.6.7.8",))
        self.assertEqual(dns_transitions(self.LIVE, new_ip), [ReconEvent.IP_CHANGED])
        self.assertEqual(dns_transitions(self.LIVE, self.LIVE), [])

    def test_cname_changed(self) -> None:
        old = DnsRecord("h.example.com", status="resolves", a=("1.2.3.4",), cname_chain=("a.cdn.net",))
        new = DnsRecord("h.example.com", status="resolves", a=("1.2.3.4",), cname_chain=("b.cdn.net",))
        self.assertEqual(dns_transitions(old, new), [ReconEvent.CNAME_CHANGED])

    def test_dangling_cname_is_flagged_once(self) -> None:
        dangling = DnsRecord("h.example.com", status="nxdomain", cname_chain=("gone.herokuapp.com",))
        self.assertTrue(is_dangling(dangling))
        self.assertIn(ReconEvent.DANGLING_CNAME, dns_transitions(None, dangling))
        # Not re-emitted when it was already dangling.
        self.assertNotIn(ReconEvent.DANGLING_CNAME, dns_transitions(dangling, dangling))


class FakeResolver:
    def __init__(self, table):
        self.table = table

    async def resolve(self, hostname):
        return self.table[hostname]


class ResolveAllTests(unittest.IsolatedAsyncioTestCase):
    async def test_bounded_resolution_dedup(self) -> None:
        table = {
            "a.example.com": DnsRecord("a.example.com", status="resolves", a=("1.1.1.1",)),
            "b.example.com": DnsRecord("b.example.com", status="nxdomain"),
        }
        records = await resolve_all(
            ["a.example.com", "A.EXAMPLE.COM.", "b.example.com"], FakeResolver(table), concurrency=5
        )
        self.assertEqual({r.hostname for r in records}, {"a.example.com", "b.example.com"})

    async def test_resolver_error_is_isolated(self) -> None:
        class Boom:
            async def resolve(self, hostname):
                raise RuntimeError("resolver crash")
        [record] = await resolve_all(["x.example.com"], Boom())
        self.assertEqual(record.status, "error")


class ReconStoreDnsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.dir, "r.db"))
        self.db.open()
        self.store = ReconStore(self.db)
        self.store.ensure_schema()

    def tearDown(self) -> None:
        self.db.close()

    def test_multiple_discovery_sources_preserved_without_duplicate_asset(self) -> None:
        with self.db.transaction():
            id1, c1 = self.store.upsert_host("api.example.com", ScopeClass.IN_SCOPE, "subfinder", "t1")
            id2, c2 = self.store.upsert_host("api.example.com", ScopeClass.IN_SCOPE, "amass", "t2")
            id3, c3 = self.store.upsert_host("api.example.com", ScopeClass.IN_SCOPE, "subfinder", "t3")
        self.assertEqual((id1, id2, id3), (id1, id1, id1))        # one asset
        self.assertEqual((c1, c2, c3), (True, False, False))       # created once
        with closing(sqlite3.connect(os.path.join(self.dir, "r.db"))) as conn:
            sources = {r[0] for r in conn.execute("SELECT source FROM discovery_sources")}
            hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        self.assertEqual(sources, {"subfinder", "amass"})          # both kept, subfinder not duplicated
        self.assertEqual(hosts, 1)

    def test_record_dns_persists_transitions(self) -> None:
        with self.db.transaction():
            hid, _ = self.store.upsert_host("h.example.com", ScopeClass.IN_SCOPE, "scope", "t1")
            e1 = self.store.record_dns(hid, DnsRecord("h.example.com", status="nxdomain"), "t1")
        with self.db.transaction():
            e2 = self.store.record_dns(hid, DnsRecord("h.example.com", status="resolves", a=("1.2.3.4",)), "t2")
        self.assertEqual(e1, [ReconEvent.NEW_SUBDOMAIN])
        self.assertEqual(e2, [ReconEvent.DNS_BECAME_LIVE])
        with closing(sqlite3.connect(os.path.join(self.dir, "r.db"))) as conn:
            status, changed = conn.execute(
                "SELECT status, changed_at FROM dns_records WHERE host_id=?", (hid,)
            ).fetchone()
        self.assertEqual(status, "resolves")
        self.assertEqual(changed, "t2")


if __name__ == "__main__":
    unittest.main()
