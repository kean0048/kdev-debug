from dmesg_agent.facts import extract_facts, render_facts

LOG = [
    "[ 1.0] Out of memory: Killed process 100 (chrome) total-vm:1kB, anon-rss:1kB",
    "[ 2.0] Out of memory: Killed process 200 (chrome) total-vm:2kB, anon-rss:2kB",
    "[ 3.0] blk_update_request: I/O error, dev sda, sector 123 op 0x0:(READ)",
    "[ 4.0] I/O error, dev sda, sector 456 op 0x0:(READ)",
    "[ 5.0] medium error, dev sdb, sector 789",
    "[ 6.0] EXT4-fs error (device sda1): ext4_find_entry:123: inode #2",
    "[ 7.0] INFO: task chrome:123 blocked for more than 120 seconds.",
    "[ 8.0] INFO: task chrome:123 blocked for more than 240 seconds.",
    "[ 9.0] watchdog: BUG: soft lockup - CPU#5 stuck for 22s! [kworker/5:1]",
    "[10.0] Kernel panic - not syncing: Fatal exception",
]

COLLECTED = """== /dev/sda
SMART overall-health self-assessment test result: PASSED
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       142
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       8
== /dev/nvme0n1
SMART overall-health self-assessment test result: PASSED
Percentage Used:                    3%
Media and Data Integrity Errors:    0
foo.service loaded failed failed Foo service
/dev/sda1 100G 95G 5G 95% /
load average: 12.00, 8.00, 4.00
Mem: 121Gi 117Gi 3.1Gi 28Gi 57Gi 4.4Gi
"""


def _by_key(facts):
    return {(f["kind"], f["key"]): f for f in facts}


def test_log_facts_aggregate():
    facts = _by_key(extract_facts(LOG))
    assert facts[("oom", "chrome")]["value"] == "killed 2 time(s); pid(s) 100, 200"
    assert facts[("oom", "chrome")]["line"] == 1
    assert facts[("io-error", "sda")]["value"] == "2 I/O error line(s)"
    assert facts[("io-error", "sdb")]["value"] == "1 I/O error line(s)"
    assert facts[("fs-error", "sda1")]["value"].startswith("1 filesystem error")
    assert facts[("hung-task", "chrome")]["value"] == "pid 123 blocked for more than 240s"
    assert facts[("soft-lockup", "cpu5")]["value"].startswith("1 occurrence")
    assert facts[("panic", "log")]["value"] == "1 matching line(s)"


def test_collected_smart_and_system_facts():
    facts = _by_key(extract_facts([], [COLLECTED]))
    assert facts[("smart-health", "sda")]["value"] == "PASSED"
    assert facts[("smart", "sda Reallocated_Sector_Ct")]["value"] == "142"
    assert facts[("smart", "sda Current_Pending_Sector")]["value"] == "8"
    assert facts[("smart", "nvme0n1 Percentage Used")]["value"] == "3%"
    assert facts[("smart", "nvme0n1 Media and Data Integrity Errors")]["value"] == "0"
    assert "foo.service" in facts[("service", "failed-units")]["value"]
    assert facts[("disk-space", "/")]["value"] == "95% used (/dev/sda1)"
    assert facts[("load", "1/5/15m")]["value"] == "12.00 / 8.00 / 4.00"
    assert "117Gi" in facts[("memory", "meminfo")]["value"]


def test_disk_below_threshold_not_reported():
    facts = extract_facts([], ["/dev/sda1 100G 50G 50G 50% /"])
    assert not any(f["kind"] == "disk-space" for f in facts)


def test_nvrm_out_of_memory_is_gpu_not_kernel_oom():
    facts = extract_facts([
        "[1.0] NVRM: nvCheckOkFailedNoLog: Check failed: Out of memory "
        "[NV_ERR_NO_MEMORY] (0x51) returned from _memdescAllocInternal",
    ])
    kinds = {(f["kind"], f["key"]) for f in facts}
    assert ("gpu-nvrm", "no_memory") in kinds
    assert not any(k == "oom" for k, _ in kinds)


def test_nvrm_other_error_codes_are_extracted():
    facts = _by_key(extract_facts([
        "[1.0] NVRM: nvAssertOkFailedNoLog: Assertion failed: Requested object not "
        "found [NV_ERR_OBJECT_NOT_FOUND] (0x57) returned from pRmApi->Control",
        "[2.0] NVRM: nvAssertOkFailedNoLog: Assertion failed: Requested object not "
        "found [NV_ERR_OBJECT_NOT_FOUND] (0x57) returned from pRmApi->Control",
    ]))
    assert facts[("gpu-nvrm", "object_not_found")]["value"] == "2 matching line(s)"


def test_edac_totals():
    facts = _by_key(extract_facts([
        "[1.0] EDAC MC0: 3 CE, 1 UE",
        "[2.0] EDAC MC0: 2 CE, 0 UE",
    ]))
    assert facts[("edac", "totals")]["value"] == "5 corrected, 1 uncorrected error(s)"


def test_render_bounds_and_empty():
    assert render_facts([]) == ""
    text = render_facts(extract_facts(LOG), max_chars=120)
    assert "facts truncated" in text
    assert len(text) < 190


def test_facts_deduplicated():
    facts = extract_facts(LOG + LOG)
    keys = [(f["kind"], f["key"]) for f in facts]
    assert len(keys) == len(set(keys))
