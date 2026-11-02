"""Native Streamlit views for local measurements, privacy controls and activity alerts."""
from datetime import datetime, time as day_time, timedelta

import pandas as pd
import streamlit as st

from .activity import ActivityMonitor
from .blocklist import normalize_target
from .history import fingerprint


@st.cache_resource
def activity_resource(path):
    return ActivityMonitor(path)


def render_rate_cards(activity, running):
    state = activity.snapshot()
    sample = state['latest'] if running else None
    with st.container(horizontal=True):
        st.metric('Download Mbps', f"{sample['download_mbps']:.3f}" if sample else '—', border=True)
        st.metric('Upload Mbps', f"{sample['upload_mbps']:.3f}" if sample else '—', border=True)
    st.caption(('Stopped' if not running else state['state']) +
               '. OS counters for the selected device adapter; interval averages, separate from NFStream attribution.')
    if sample:
        st.caption(f"Latest counter interval: {sample['seconds']:.1f} seconds. No rates are inferred from completed-flow totals.")


def period_bounds(period, now=None, dates=None):
    now = now or datetime.now().astimezone()
    end = now.timestamp() + 1
    if period == 'Last 15 minutes':
        start = end - 900
    elif period == 'Last hour':
        start = end - 3600
    elif period == 'Today':
        start = datetime.combine(now.date(), day_time.min, tzinfo=now.tzinfo).timestamp()
    elif period == 'Custom' and dates and len(dates) == 2:
        start = datetime.combine(dates[0], day_time.min, tzinfo=now.tzinfo).timestamp()
        end = datetime.combine(dates[1] + timedelta(days=1), day_time.min, tzinfo=now.tzinfo).timestamp()
    else:
        start = end - 7 * 86400
    return start, end


def render_history(activity, snapshot):
    activity.maintain()
    st.subheader('Bandwidth history')
    period = st.selectbox('Time period', ['Last 15 minutes', 'Last hour', 'Today', 'Last 7 days', 'Custom'],
                          key='history_period')
    dates = None
    if period == 'Custom':
        today = datetime.now().date()
        dates = st.date_input('History date range', (today - timedelta(days=6), today), key='history_dates')
        if not isinstance(dates, tuple) or len(dates) != 2:
            st.info('Select both the start and end date.')
            return
    start, end = period_bounds(period, dates=dates)
    samples = activity.store.query('usage', start, end) if activity.config['enabled'] else []
    if not activity.config['enabled']:
        samples = [dict(row, minute=row['timestamp']) for row in activity.snapshot()['samples']
                   if start <= row['timestamp'] < end]
    if samples:
        frame = pd.DataFrame(samples)
        adapters = sorted(frame['adapter'].unique())
        selected = st.selectbox('Measured adapter history', adapters,
                                format_func=lambda key: 'Device adapter ' + key[:8], key='history_adapter')
        frame = frame[frame['adapter'] == selected].copy()
        frame['Time (UTC)'] = pd.to_datetime(frame['minute'], unit='s', utc=True)
        frame['Download Mbps'] = frame['download'] * 8 / frame['seconds'] / 1_000_000
        frame['Upload Mbps'] = frame['upload'] * 8 / frame['seconds'] / 1_000_000
        st.line_chart(frame.set_index('Time (UTC)')[['Download Mbps', 'Upload Mbps']],
                      color=['#1536A6', '#06B6D4'], alt='Measured adapter throughput averaged over observed intervals')
        st.caption(f"Observed adapter bytes: {(frame['download'].sum() + frame['upload'].sum()) / 1_000_000:.2f} MB. "
                   'Minute buckets include only sampled intervals; gaps and application downtime are unmeasured.')
    else:
        st.info('No adapter measurements in this time period. Start monitoring on a supported adapter to collect real samples.')
    st.caption('This device only. Counter bytes and completed-flow bytes measure different boundaries and must not be added. '
               'VPNs, offload, loopback and multiple adapters can cause overlap or differences. No router-wide usage is inferred.')
    if activity.store.error:
        st.warning(activity.store.error)
    if activity.dropped_events or activity.ingestion_error:
        st.warning(activity.ingestion_error or f'{activity.dropped_events} activity events exceeded the local queue limit. History has gaps; capture counters remain separate.')

    st.subheader('Website & application usage')
    archived = activity.store.query('flows', start, end) if activity.config['enabled'] else []
    if archived:
        st.caption(f"Stored completed flows in this period: {sum(row['count'] for row in archived):,}; "
                   f"observed bytes: {sum(row['bytes'] for row in archived) / 1_000_000:.2f} MB.")
    rows = archived if activity.config['enabled'] and activity.config['names'] else [
        row for row in activity.snapshot()['flows'] if start <= row['timestamp'] < end]
    if not activity.config['names']:
        st.caption('Names are not persisted. Named charts use up to 5,000 in-memory flows; optional named history is available in Settings.')
    if not rows:
        st.info('No attributed activity in this period.')
        return
    frame = pd.DataFrame(rows)
    frame['service'] = frame['service'].replace('', 'Not stored')
    frame['process'] = frame['process'].replace('', 'Not stored')
    with st.expander('Usage filters'):
        services = st.multiselect('Service', sorted(frame['service'].unique()), key='history_services')
        processes = st.multiselect('Process', sorted(frame['process'].unique()), key='history_processes')
        protocols = st.multiselect('Protocol', ['TCP', 'UDP', 'Other'], key='history_protocols')
        statuses = st.multiselect('Identification', ['Identified', 'Unknown', 'Ambiguous'], key='history_statuses')
    for field, selected in [('service', services), ('process', processes), ('protocol', protocols), ('status', statuses)]:
        if selected:
            frame = frame[frame[field].isin(selected)]
    left, right = st.columns(2)
    with left:
        st.caption('Top identified services · observed completed-flow bytes')
        known = frame[~frame['service'].isin(['Unknown', 'Ambiguous', 'Not stored'])]
        if not known.empty:
            st.bar_chart(known.groupby('service')['bytes'].sum().nlargest(10), color='#1536A6',
                         alt='Top services by completed-flow bytes in selected period')
        else:
            st.info('No identified services for these filters.')
    with right:
        st.caption('Top Windows processes · exact socket evidence')
        known = frame[~frame['process'].isin(['Unknown Process', 'Not stored'])]
        if not known.empty:
            st.bar_chart(known.groupby('process')['bytes'].sum().nlargest(10), color='#06B6D4',
                         alt='Top reliably attributed process names by observed bytes')
        else:
            st.info('No reliable process attribution for these filters.')
    if not frame.empty:
        summary = frame.groupby('service').agg(Bytes=('bytes', 'sum'), Flows=('count', 'sum'),
                                               Upload_bytes=('upload', lambda values: values.sum(min_count=1)),
                                               Download_bytes=('download', lambda values: values.sum(min_count=1)),
                                               Last_seen=('last_seen', 'max')).sort_values('Bytes', ascending=False).head(10)
        summary['Last_seen'] = pd.to_datetime(summary['Last_seen'], unit='s', utc=True)
        st.dataframe(summary, alt='Service byte totals, flow counts and last observed connection time')
        st.caption('Directional totals include only flows with one verified local endpoint. Blank values mean unknown direction.')
    destinations = []
    for row in snapshot['flows']:
        target = row.get('Remote IP') or (row.get('Detected Hostname') if row.get('Identification Status') == 'Hostname evidence' else None)
        if not target:
            continue
        timestamp = row.get('bidirectional_last_seen_ms')
        if timestamp is None:
            continue
        status = 'Unknown' if row.get('Detected Service', 'Unknown') == 'Unknown' else 'Ambiguous' if row.get('Detected Service') == 'Ambiguous' else 'Identified'
        if not start <= float(timestamp) / 1000 < end:
            continue
        if services and row.get('Detected Service') not in services or processes and row.get('Process Name') not in processes:
            continue
        if protocols and {6: 'TCP', 17: 'UDP'}.get(row.get('protocol'), 'Other') not in protocols or statuses and status not in statuses:
            continue
        destinations.append({'Destination': target, 'Bytes': row.get('bidirectional_bytes', 0)})
    if destinations:
        st.caption('Top remote destinations · recent capture only; endpoints are never saved in history')
        st.bar_chart(pd.DataFrame(destinations).groupby('Destination')['Bytes'].sum().nlargest(10),
                     color='#1536A6', alt='Recent remote destinations by observed bytes; retained in memory only')


@st.fragment(run_every='2s')
def render_alerts(activity):
    activity.touch()
    st.subheader('Activity alerts')
    rows = activity.alerts()
    seen = set(st.session_state.get('activity_toast_ids', [row['id'] for row in rows]))
    new = [row for row in rows if row['id'] not in seen and not row['read']]
    for row in new[:3]:
        st.toast(f"{row['severity']}: {row['message']}")
    st.session_state['activity_toast_ids'] = [row['id'] for row in rows]
    unread = sum(not row['read'] for row in rows)
    st.caption(f'{unread} unread · local notifications only. Unknown traffic is not classified as malicious.')
    if not rows:
        st.info('No activity alerts. Configure thresholds and privacy in Settings.')
        return
    frame = pd.DataFrame(rows)
    frame['Time (UTC)'] = pd.to_datetime(frame['timestamp'], unit='s', utc=True)
    st.dataframe(frame[['Time (UTC)', 'kind', 'severity', 'message', 'read']], hide_index=True,
                 alt='Local informational events and warnings with read state')
    st.button('Mark all alerts read', key='activity_read', on_click=activity.alert_action, args=('read',))
    selected = st.selectbox('Alert to dismiss', [row['id'] for row in rows],
                            format_func=lambda key: next(row['kind'] + ' · ' + datetime.fromtimestamp(row['timestamp']).isoformat(timespec='seconds') for row in rows if row['id'] == key),
                            key='activity_selected_alert')
    st.button('Dismiss selected alert', key='activity_dismiss', on_click=activity.alert_action, args=('dismiss', selected))
    st.button('Clear alert history', key='activity_clear_alerts', on_click=activity.alert_action, args=('clear',))


def render_activity_settings(activity):
    st.subheader('Local history and activity alerts')
    config = activity.config
    st.caption('SQLite stays on this device. No payloads, hostnames, IP addresses or executable paths are saved. '
               'Optional names are service labels and process basenames. Existing records remain until retention or Clear history removes them.')
    if activity.store.error:
        st.warning(activity.store.error)
        if st.button('Retry local history', key='activity_retry'):
            activity.store._prepare()
            st.rerun()
    with st.form('activity_settings'):
        updated = dict(config)
        updated['enabled'] = st.checkbox('Save aggregate usage locally', value=config['enabled'])
        updated['names'] = st.checkbox('Also save service and process names', value=config['names'])
        updated['save_alerts'] = st.checkbox('Save alert history locally', value=config['save_alerts'])
        updated['retention_days'] = st.number_input('History retention (days)', 1, 30, int(config['retention_days']))
        for key, label in [('new_service', 'New identified service'), ('new_process', 'New reliably attributed Windows process'),
                           ('high_usage', 'High observed usage'), ('repeated', 'Repeated connections to selected destination'),
                           ('blocking', 'Managed blocking status changes')]:
            updated[key] = st.checkbox(label, value=config[key])
        updated['bandwidth_mbps'] = st.number_input('Adapter Mbps alert threshold (either direction)', 0.01, 1_000_000.0, float(config['bandwidth_mbps']))
        updated['usage_mb'] = st.number_input('Completed-flow usage threshold (MB per window)', 0.01, 1_000_000.0, float(config['usage_mb']))
        updated['window_seconds'] = st.number_input('Connection and flow-usage window (seconds)', 10, 3600, int(config['window_seconds']))
        updated['connection_count'] = st.number_input('Connections in window', 2, 10000, int(config['connection_count']))
        updated['cooldown_seconds'] = st.number_input('Minimum seconds between alerts for the same event type/target', 5, 3600, int(config['cooldown_seconds']))
        target = st.text_input('Destination for repeated-connection alerts (optional)',
                               help='Enter an exact IP or hostname. Only its comparison fingerprint is stored; leave blank to keep the current target.')
        forget = st.checkbox('Forget the configured destination')
        if config['destination_key']:
            st.caption('A destination fingerprint is configured. It is not an anonymization guarantee.')
        if st.form_submit_button('Save history and alert settings'):
            try:
                if forget:
                    updated['destination_key'] = ''
                elif target.strip():
                    updated['destination_key'] = fingerprint(normalize_target(target))
                if updated['repeated'] and not updated['destination_key']:
                    raise ValueError('Choose a destination before enabling repeated-connection alerts.')
                if not activity.configure(updated):
                    raise ValueError(activity.store.error or 'Could not save settings.')
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success('Saved local history and alert settings.')
                st.rerun()
    confirmed = st.checkbox('Delete all stored usage, named summaries and alerts', key='activity_confirm_clear')
    if st.button('Clear all local history', disabled=not confirmed, key='activity_clear_history'):
        if activity.clear_history():
            st.success('Stored history and alert state cleared. Current capture counters are unchanged.')
        else:
            st.error(activity.store.error or 'History could not be cleared.')
