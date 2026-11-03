"""Streamlit controls for explicit, device-local blocking previews and rollback."""
import hashlib

import pandas as pd
import streamlit as st
from .streamlit_compat import alt_text

from . import blocklist, domain_blocker, firewall
from .blocking_center import (SCOPE, eligible_service_hosts, entry_status,
                              is_windows_admin, observed_services, preview_domain,
                              preview_ip, remote_ip_candidates, website_candidates)


def _clear_preview():
    st.session_state["block_preview"] = []


def _save_intents(previews):
    outcomes = []
    for preview in previews:
        added, message = blocklist.add_target(
            preview["target"], kind=preview["type"], service=preview.get("service"),
            evidence=preview.get("evidence"))
        outcomes.append(message)
    return outcomes


def _recheck(preview, recent_flows):
    if preview["type"] == "IP":
        return preview_ip(preview["target"], preview["direction"])
    if preview["type"] == "Website" and preview.get("service"):
        current = {item["hostname"] for item in eligible_service_hosts(
            recent_flows, preview["service"])}
        if preview["target"] not in current:
            raise ValueError("The observed hostname evidence is no longer available. Preview it again or enter the domain manually.")
    return preview_domain(preview["target"], kind=preview["type"],
                          service=preview.get("service"), evidence=preview.get("evidence"))


@st.dialog("Confirm Windows enforcement", width="medium")
def confirm_enforcement(previews, recent_flows):
    st.markdown(f"**Scope: {SCOPE}.** Passive monitoring does not enforce these rules.")
    st.dataframe(pd.DataFrame([{"Target": item["target"], "Type": item["type"],
                                "Method": item["method"], "Direction": item.get("direction", "exact hostname"),
                                "Exact coverage": item["coverage"]}
                               for item in previews]), hide_index=True,
                 **alt_text(st.dataframe, "Exact Windows rules awaiting confirmation"))
    st.caption("Hosts entries cover only the exact listed names. IP rules may affect unrelated services on shared infrastructure.")
    phrase = st.text_input("Type BLOCK to confirm these exact targets", key="confirm_block_phrase")
    critical = [reason for item in previews for reason in item.get("critical_reasons", [])]
    extra = False
    if critical:
        st.warning("Critical network address: " + ", ".join(sorted(set(critical))))
        extra = st.checkbox("I understand this may disrupt this device's network access",
                            key="confirm_critical_ip")
    if st.button("Apply blocking rules", type="primary", key="apply_blocking_rules"):
        if phrase != "BLOCK":
            st.error("Type BLOCK before applying any Windows rule.")
            return
        if critical and not extra:
            st.error("Confirm the critical-address warning before applying.")
            return
        if not is_windows_admin():
            st.error("Administrator permissions are required. Restart Streamlit from an elevated PowerShell window.")
            return
        try:
            checked = [_recheck(item, recent_flows) for item in previews]
        except (ValueError, RuntimeError) as exc:
            st.error(f"Rule preview changed: {exc}")
            return
        errors = []
        for item in checked:
            try:
                blocklist.add_target(item["target"], kind=item["type"],
                                     service=item.get("service"), evidence=item.get("evidence"))
                if item["type"] == "IP":
                    firewall.block_ip(item["target"], confirmed=True,
                                      direction=item["direction"], critical_confirmed=extra)
                    state = firewall.managed_rule_state(item["target"], item["direction"])
                    if state != "active":
                        raise RuntimeError(f"Firewall rule state is {state} after applying.")
                else:
                    domain_blocker.block_domain(item["target"], confirmed=True)
                    if not domain_blocker.is_domain_blocked(item["target"]):
                        raise RuntimeError("Managed hosts entry could not be verified.")
            except (OSError, RuntimeError, ValueError, PermissionError) as exc:
                errors.append(f"{item['target']}: {exc}")
        if errors:
            for message in errors:
                st.error(message)
            st.warning("Some intended targets may now be active. Refresh the status table before retrying or undoing.")
        else:
            st.session_state["blocking_notice"] = f"Verified {len(checked)} enabled managed rule(s) on this device."
            st.session_state["block_preview"] = []
            st.rerun()


@st.dialog("Confirm undo or removal", width="medium")
def confirm_removal(entry):
    target = entry["target"]
    state = entry_status(entry)
    st.markdown(f"**Target:** `{target}`")
    st.caption(f"Scope: {SCOPE}. Current status: {state['status']}.")
    if state["error"] or "conflict" in state["states"].values():
        st.error(state["error"] or "A conflicting rule requires manual review. Nothing was removed.")
        return
    st.caption("Undo removes only managed Windows rules or hosts entries for this exact target, then removes its local intent record.")
    phrase = st.text_input("Type REMOVE to confirm", key="confirm_remove_phrase")
    if st.button("Undo / remove target", key="apply_remove_target"):
        if phrase != "REMOVE":
            st.error("Type REMOVE before changing this target.")
            return
        if any(value in ("active", "disabled") for value in state["states"].values()) and not is_windows_admin():
            st.error("Administrator permissions are required to undo an active Windows rule.")
            return
        try:
            if entry["type"] == "IP":
                for direction, rule_state in state["states"].items():
                    if rule_state in ("active", "disabled"):
                        firewall.unblock_ip(target, direction=direction, confirmed=True)
                after = entry_status(entry)
                if after["error"] or any(value != "absent" for value in after["states"].values()):
                    raise RuntimeError("A managed firewall rule remains; the intent was retained.")
            elif state["states"].get("domain") == "active":
                domain_blocker.unblock_domain(target, confirmed=True)
                if domain_blocker.is_domain_blocked(target):
                    raise RuntimeError("The hosts entry remains; the intent was retained.")
            blocklist.remove_target(target)
        except (OSError, RuntimeError, ValueError) as exc:
            st.error(f"Could not safely undo {target}: {exc}")
            return
        st.session_state["blocking_notice"] = f"Removed the managed rule and intent for {target}."
        st.rerun()


def _render_advanced_inputs(recent_flows):
    ip_tab, domain_tab, website_tab = st.tabs(["IP address", "Domain", "Website / service"])
    with ip_tab:
        st.caption("An exact remote IPv4 or IPv6 address. Outbound is the default; inbound is an advanced option.")
        with st.form("preview_ip_form"):
            ip_text = st.text_input("Remote IP address", placeholder="192.0.2.10 or 2001:db8::10")
            inbound = st.checkbox("Advanced: propose inbound instead of outbound", key="inbound_ip_option")
            if st.form_submit_button("Preview IP rule"):
                try:
                    st.session_state["block_preview"] = [preview_ip(ip_text, "in" if inbound else "out")]
                except (ValueError, RuntimeError) as exc:
                    st.session_state["block_preview"] = []
                    st.error(str(exc))
    with domain_tab:
        st.caption("One exact hostname through the managed hosts-file section. Wildcards and subdomains are not included.")
        with st.form("preview_domain_form"):
            domain_text = st.text_input("Exact domain", placeholder="example.com")
            if st.form_submit_button("Preview domain entry"):
                try:
                    st.session_state["block_preview"] = [preview_domain(domain_text)]
                except ValueError as exc:
                    st.session_state["block_preview"] = []
                    st.error(str(exc))
    with website_tab:
        services = observed_services(recent_flows)
        if not services:
            st.info("No recognized services in recent activity. Use the Domain tab for a manually verified hostname.")
        else:
            service = st.selectbox("Detected service", services, key="blocking_service",
                                   on_change=_clear_preview)
            candidates = eligible_service_hosts(recent_flows, service)
            if candidates:
                st.dataframe(pd.DataFrame(candidates), hide_index=True,
                             **alt_text(st.dataframe, "Observed hostnames and protocol evidence for the selected service"))
                names = [item["hostname"] for item in candidates]
                selected = st.multiselect("Exact hostnames to propose", names, key="blocking_hostnames",
                                          on_change=_clear_preview)
                if st.button("Preview selected hostnames", key="preview_website_targets"):
                    if not selected:
                        st.error("Select at least one observed hostname.")
                    else:
                        evidence = {item["hostname"]: item["evidence"] for item in candidates}
                        st.session_state["block_preview"] = [
                            preview_domain(host, kind="Website", service=service,
                                           evidence=evidence[host]) for host in selected]
            else:
                st.warning("This service has no direct hostname evidence in recent flows. No website rule can be proposed. Use a verified exact domain in the Domain tab.")


def _prefill_observed_target(item):
    """A user click fills the form; it never applies a Windows rule."""
    st.session_state["monitor_block_type"] = item["type"]
    st.session_state["monitor_block_target"] = item["target"]
    st.session_state["block_preview"] = []
    st.session_state["monitor_prefill_notice"] = f"Filled {item['target']}. Review the exact preview before enforcement."


def _quick_target_row(item, *, description):
    digest = hashlib.sha256((item["type"] + ":" + item["target"] + ":" +
                             str(item.get("service", ""))).encode()).hexdigest()[:16]
    label, action = st.columns([5, 2], vertical_alignment="center")
    with label:
        st.markdown(description)
        if item.get("evidence"):
            st.caption(f"Evidence: {item['evidence']}")
    with action:
        st.button(f"Block {item['target']}", key=f"quick_block_{digest}",
                  on_click=_prefill_observed_target, args=(item,),
                  help="Fill the exact target in the blocking form; no rule is applied yet.")


def _render_monitor_inputs(recent_flows):
    websites = website_candidates(recent_flows)
    remote_ips = remote_ip_candidates(recent_flows)
    st.caption("Quick actions fill an exact target. Service labels are observations, not firewall rules or Random Forest identities.")
    st.button("Refresh observed targets", key="refresh_block_candidates",
              help="Read the latest completed flows without changing a pending preview.",
              icon=":material/refresh:")
    if websites:
        st.markdown("**Observed websites and services**")
        for item in websites[:6]:
            _quick_target_row(item, description=f"**{item['service']}** · `{item['target']}`")
    if remote_ips:
        st.markdown("**Observed remote IP addresses**")
        for ip in remote_ips[:6]:
            _quick_target_row({"target": ip, "type": "IP"}, description=f"Remote IP · `{ip}`")
    if not websites and not remote_ips:
        st.caption("No directly evidenced hostname or remote IP is available in recent flows. Enter a target manually below.")
    if notice := st.session_state.pop("monitor_prefill_notice", None):
        st.info(notice)
    with st.form("monitor_preview_form"):
        kind = st.selectbox("Blocking type", ["Website", "Domain", "IP"],
                            key="monitor_block_type")
        target = st.text_input("Exact observed hostname, domain, or remote IP",
                               key="monitor_block_target",
                               placeholder="Select Block above or enter an exact target")
        if st.form_submit_button("Preview target"):
            try:
                if kind == "IP":
                    preview = preview_ip(target)
                elif kind == "Domain":
                    preview = preview_domain(target)
                else:
                    normalized = domain_blocker._validate_domain(target)
                    match = next((item for item in website_candidates(recent_flows)
                                  if item["target"] == normalized), None)
                    if match is None:
                        raise ValueError("Choose an observed hostname for Website, or use Domain for a manually verified name.")
                    preview = preview_domain(normalized, kind="Website",
                                             service=match["service"], evidence=match["evidence"])
                st.session_state["block_preview"] = [preview]
            except (ValueError, RuntimeError) as exc:
                st.session_state["block_preview"] = []
                st.error(str(exc))


def render_monitor_blocking(recent_flows):
    """Daily Monitor controls; Settings uses the same backend with advanced inputs."""
    render_blocking_center(recent_flows, compact=True)


def render_blocking_center(recent_flows, *, compact=False):
    st.header("Blocking & Protection")
    st.info("This Windows device only. NFStream and service detection observe traffic; Windows Firewall and the managed hosts section enforce selected rules. A present rule does not prove every connection is blocked.")
    admin = is_windows_admin()
    if not admin:
        st.warning("Administrator permissions are needed to enforce or undo active Windows rules. You can still preview and save an intent.")
    if notice := st.session_state.pop("blocking_notice", None):
        st.success(notice)
    if compact:
        _render_monitor_inputs(recent_flows)
    else:
        _render_advanced_inputs(recent_flows)

    previews = st.session_state.get("block_preview", [])
    if previews:
        with st.container(border=True):
            st.subheader("Rule preview")
            rows = [{"Target": item["target"], "Type": item["type"],
                     "Enforcement method": item["method"],
                     "Direction": item.get("direction", "exact hostname"),
                     "Scope": item["scope"], "Coverage": item["coverage"]} for item in previews]
            st.dataframe(pd.DataFrame(rows), hide_index=True,
                         **alt_text(st.dataframe, "Preview of exact device-local firewall or hosts rules"))
            if any(item["type"] == "IP" for item in previews):
                st.warning("Shared hosting and CDN addresses may serve unrelated sites. An IP rule can disrupt more than the named service.")
            for item in previews:
                if item["critical_reasons"]:
                    st.warning(f"{item['target']} may be critical: {', '.join(item['critical_reasons'])}. Extra confirmation is required.")
            save_col, enforce_col = st.columns(2)
            with save_col:
                if st.button("Save intent only", key="save_block_intent"):
                    for outcome in _save_intents(previews):
                        st.info(outcome)
            with enforce_col:
                if st.button("Review and enforce", type="primary", key="open_block_dialog",
                             disabled=not admin):
                    confirm_enforcement(previews, recent_flows)

    st.subheader("Intended and active rules")
    entries = blocklist.list_entries()
    if not entries:
        st.caption("No targets saved. A preview alone does not change this device.")
        return
    inventory, inventory_error = [], None
    if any(item["type"] == "IP" for item in entries):
        try:
            inventory = firewall._managed_rules()
        except RuntimeError as exc:
            inventory_error = str(exc)
    status_by_target = {
        item["target"]: ({"status": "Status unavailable", "states": {}, "error": inventory_error}
                         if item["type"] == "IP" and inventory_error
                         else entry_status(item, rules=inventory))
        for item in entries}
    rows = [{"Target": item["target"], "Type": item["type"],
             "Enforcement method": "Windows Firewall" if item["type"] == "IP" else "Managed hosts entry",
             "Scope": SCOPE, "Status": status_by_target[item["target"]]["status"],
             "Created date (UTC)": item["created"], "Remove / Undo": "Select below"}
            for item in entries]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                 **alt_text(st.dataframe, "Saved intended targets and verified device-local enforcement status"))
    selected_target = st.selectbox("Manage saved target", [item["target"] for item in entries],
                                   key="managed_block_target")
    selected_entry = next(item for item in entries if item["target"] == selected_target)
    selected_status = status_by_target[selected_target]
    if selected_entry.get("service"):
        st.caption(f"Website evidence: {selected_entry['service']} — {selected_entry.get('evidence') or 'observed hostname'}")
    if selected_status["error"]:
        st.error(f"Could not verify this target: {selected_status['error']}")
    manage_col, remove_col = st.columns(2)
    with manage_col:
        if st.button("Preview enforcement for target", key="preview_saved_target",
                     disabled=bool(selected_status["error"])):
            try:
                st.session_state["block_preview"] = [
                    preview_ip(selected_target) if selected_entry["type"] == "IP"
                    else preview_domain(selected_target, kind=selected_entry["type"],
                                        service=selected_entry.get("service"),
                                        evidence=selected_entry.get("evidence"))]
                st.rerun()
            except (ValueError, RuntimeError) as exc:
                st.error(str(exc))
    with remove_col:
        active = any(value in ("active", "disabled") for value in selected_status["states"].values())
        if st.button("Remove / Undo selected", key="open_remove_dialog",
                     disabled=bool(selected_status["error"]) or
                     "conflict" in selected_status["states"].values() or (active and not admin)):
            confirm_removal(selected_entry)
