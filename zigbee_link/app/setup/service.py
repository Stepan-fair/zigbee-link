"""Bounded discovery scheduling independent of interface and recovery workers."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from ipaddress import IPv4Network
import time
from .model import Catalog, FieldValue
from .matching import match_networks, suggest_references
from .supervisor import DiscoverySourceError


class DiscoveryService:
    def __init__(self, reader, store, collector_factory, clock=time.monotonic,
                 subnet=IPv4Network("172.31.254.0/24")):
        self.reader, self.store, self.collector_factory, self.clock = reader, store, collector_factory, clock
        self.subnet = subnet
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="zigbee-discovery")
        self.future = self.collector = self.retired = None
        self.connection = self.connection_override = None
        self.apps_metadata = ()
        self.deadline = self.next_scan = 0
        self.last_scan = float("-inf")
        self.failures = 0
        self.closed = False
        self.issues = ()

    def set_connection(self, connection):
        self.connection_override = connection

    def _read_sources(self):
        connection = self.connection_override or self.reader.mqtt_service(scan=True)
        apps = self.reader.apps()
        return connection, apps, self.reader.issues

    def request_scan(self):
        now = self.clock()
        if self.closed or self.future is not None or self.collector is not None or now - self.last_scan < 60:
            return False
        if self.retired is not None:
            if not self.retired.cleanup_done.is_set() or not self.retired.cleanup_ok:
                self.issues = ("mqtt_cleanup_pending",)
                return False
            self.retired = None
        self.last_scan, self.deadline = now, now + 30
        # Reader uses real monotonic time; an injected scheduler clock only controls tests/scheduling.
        self.reader.begin_scan(time.monotonic() + 30)
        self.future = self.pool.submit(self._read_sources)
        self.issues = ()
        return True

    def _finish(self):
        bridges, devices, issues = self.collector.snapshot() if self.collector else ((), {}, ())
        if self.collector:
            self.collector.close()
            self.retired, self.collector = self.collector, None
        self.issues = tuple(dict.fromkeys((*self.issues, *issues)))
        if self.connection:
            rows = match_networks(self.apps_metadata, bridges, broker=self.connection.record, subnet=self.subnet)
            completed = []
            for row in rows:
                topic = row.fields["base_topic"].value
                refs = suggest_references(devices.get(topic, ()))
                fields = dict(row.fields)
                fields["references"] = FieldValue("auto", [asdict(r) for r in refs], "mqtt", time.time(), "unverified")
                row_issues = row.issues if refs else tuple(dict.fromkeys((*row.issues, "radio_reference_unavailable")))
                completed.append(replace(row, fields=fields, issues=row_issues))
            catalog = self.store.catalog()
            self.store.save_catalog(Catalog(catalog.revision, tuple(completed), self.issues), expected_revision=catalog.revision)
        else:
            catalog = self.store.catalog()
            proposals = match_networks(self.apps_metadata, (), broker=None, subnet=self.subnet) if self.apps_metadata else catalog.candidates
            self.store.save_catalog(replace(catalog, candidates=proposals,
                                    issues=tuple(dict.fromkeys((*self.issues, "mqtt_unconfigured")))), expected_revision=catalog.revision)
        self.next_scan = self.clock() + min(3600, 300 * 2 ** min(self.failures, 4))

    def tick(self):
        if self.closed:
            return
        now = self.clock()
        if self.future is not None:
            if now >= self.deadline:
                self.reader.cancel_scan()
            if not self.future.done():
                return
            future, self.future = self.future, None
            try:
                self.connection, self.apps_metadata, self.issues = future.result()
                self.failures = 0
                if self.connection and now < self.deadline:
                    self.collector = self.collector_factory(self.connection)
                    known = tuple(dict.fromkeys(a.base_topic for a in self.apps_metadata if a.base_topic))
                    self.collector.start(known, discover_unknown=not self.apps_metadata or any(not a.base_topic for a in self.apps_metadata),
                                         deadline=self.deadline)
                else:
                    self._finish()
            except DiscoverySourceError as exc:
                self.issues = (str(exc),)
                self.failures += 1
                self.connection = None
                self.apps_metadata = ()
                self._finish()
            return
        if self.collector is not None:
            self.collector.tick(now)
            if not self.collector.active:
                self._finish()
        elif now >= self.next_scan:
            self.request_scan()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.reader.cancel_scan()
        if self.collector:
            self.collector.close()
        if self.future:
            self.future.cancel()
        self.pool.shutdown(wait=True, cancel_futures=True)
