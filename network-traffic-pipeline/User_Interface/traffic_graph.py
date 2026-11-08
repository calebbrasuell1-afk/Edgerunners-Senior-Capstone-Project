"""Streamlit traffic chart for the dashboard's open SQLite connection."""
import altair as alt
import pandas as pd
import streamlit as st


def show_traffic_graph(connection):
    st.subheader("Traffic over time")
    hosts = pd.read_sql_query(
        "SELECT ip FROM hosts ORDER BY fanout DESC, ip LIMIT 200", connection
    )["ip"].tolist()
    if not hosts:
        st.info("No hosts are available yet.")
        return

    ip = st.selectbox("Choose a host", hosts)
    frame = pd.read_sql_query(
        "SELECT bucket, pkts_in, pkts_out FROM host_buckets "
        "WHERE ip = ? ORDER BY bucket", connection, params=(ip,)
    )
    if frame.empty:
        st.info("No traffic was recorded for this host.")
        return

    frame = frame.rename(columns={"pkts_in": "Incoming", "pkts_out": "Outgoing"})
    frame["Minute"] = pd.to_datetime(frame["bucket"], unit="s", utc=True)
    frame["UTC"] = frame["Minute"].dt.strftime("%Y-%m-%d %H:%M")
    frame["Total"] = frame["Incoming"] + frame["Outgoing"]
    peaks = frame.loc[frame["Total"] == frame["Total"].max()]
    first = peaks.iloc[0]
    st.metric("Peak traffic · incoming + outgoing", f"{first['Total']:,} packets")
    st.caption(f"{ip} · {first['UTC']} UTC · "
               f"{first['Incoming']:,} incoming + {first['Outgoing']:,} outgoing")
    if len(peaks) > 1:
        st.caption(f"{len(peaks)} minutes tied for the peak. The first is listed above.")

    long = frame.melt(id_vars=["Minute", "UTC"], value_vars=["Incoming", "Outgoing", "Total"],
                      var_name="Traffic", value_name="Packets")
    x = alt.X("Minute:T", title="Time (UTC)", scale=alt.Scale(type="utc"),
              axis=alt.Axis(format="%H:%M", tickCount=6))
    y = alt.Y("Packets:Q", title="Packets per minute", scale=alt.Scale(zero=True))
    colors = alt.Color("Traffic:N", title=None, scale=alt.Scale(
        domain=["Incoming", "Outgoing", "Total"], range=["#3999da", "#24aa84", "#a878d2"]
    ), legend=alt.Legend(orient="bottom"))
    tooltip = [alt.Tooltip("UTC:N", title="Minute (UTC)"), "Traffic:N",
               alt.Tooltip("Packets:Q", format=",d")]
    if len(frame) == 1:
        chart = alt.Chart(long).mark_bar(size=40).encode(
            x=alt.X("Traffic:N", title=None, sort=["Incoming", "Outgoing", "Total"]),
            y=y, color=colors, tooltip=tooltip)
        st.caption("One minute recorded. Bars show the counts for that minute.")
    else:
        lines = alt.Chart(long).mark_line(point=True).encode(x=x, y=y, color=colors, tooltip=tooltip)
        peak_marks = alt.Chart(peaks).mark_point(
            shape="diamond", size=160, filled=True, color="#e59128"
        ).encode(x=x, y=alt.Y("Total:Q", title="Packets per minute"),
                 tooltip=[alt.Tooltip("UTC:N", title="Peak minute (UTC)"),
                          alt.Tooltip("Total:Q", title="Total packets", format=",d")])
        chart = lines + peak_marks
        st.caption("Diamonds mark peak total traffic. Hover over a point for exact counts.")
    st.altair_chart(chart.properties(height=320), use_container_width=True)