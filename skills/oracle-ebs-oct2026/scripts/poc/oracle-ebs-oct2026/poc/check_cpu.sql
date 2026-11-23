-- CVE-2026-101809 / CVE-2026-101767 - Oracle EBS patch-level evidence (read-only).
-- Run as APPS (or a read-only DBA account). Touches no business data.
-- Compare the output with the EBS patch list in Oracle's October 2026 CPU
-- (cpuoct2026.html, "Oracle E-Business Suite" patch-availability document).
-- For authorized security testing only.
set lines 200 pages 100
prompt == release
select release_name from fnd_product_groups;
prompt == AD/TXK code levels
select abbreviation, codelevel from ad_trackable_entities where abbreviation in ('ad','txk','fnd','fwk');
prompt == patches applied since the October 2026 CPU (2026-10-20)
select b.bug_number, max(b.creation_date) applied
  from ad_bugs b
 where b.creation_date >= date '2026-10-20'
 group by b.bug_number
 order by applied desc;
prompt == if empty: October 2026 CPU not applied -> AFFECTED on 12.2.3-12.2.15
