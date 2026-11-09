"""All network graph views for the dashboard. Entry point: show_graphs(database_path)."""
import json
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

D3 = '<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>'
STYLE = "<style>body{margin:0;background:#111;color:#ddd;font:11px sans-serif}</style>"


def _render(tpl, data, height):
    html = D3 + STYLE + tpl.replace("__DATA__", json.dumps(data))
    components.html(html, height=height, scrolling=True)


# ---------------------------------------------------------------- TimeArcs
TIMEARCS = """
<div id="c"></div><script>
const D=__DATA__, rh=18, m={l:140,r:20,t:30,b:10}, W=1100;
const H=D.hosts.length*rh+m.t+m.b;
const svg=d3.select("#c").append("svg").attr("width",W).attr("height",H);
const x=d3.scaleUtc().domain([new Date(D.t0*1000),new Date(D.t1*1000)]).range([m.l,W-m.r]);
const y=d3.scalePoint().domain(D.hosts).range([m.t,H-m.b]).padding(0.5);
const info=svg.append("text").attr("x",6).attr("y",14).attr("fill","#ddd");
svg.append("g").attr("transform","translate(0,20)").call(d3.axisTop(x).ticks(8)).selectAll("text").attr("fill","#ddd");
svg.selectAll(".row").data(D.hosts).join("line").attr("x1",m.l).attr("x2",W-m.r)
  .attr("y1",d=>y(d)).attr("y2",d=>y(d)).attr("stroke","#333");
const labels=svg.selectAll(".lab").data(D.hosts).join("text").style("cursor","pointer")
  .attr("x",m.l-6).attr("y",d=>y(d)+3).attr("text-anchor","end").text(d=>d);
const arcs=svg.selectAll("path.arc").data(D.arcs).join("path").style("cursor","pointer")
  .attr("fill","none")
  .attr("stroke-width",d=>Math.min(4,0.5+Math.log10(d.n+1)))
  .attr("d",d=>{const a=y(d.s),b=y(d.t),r=Math.abs(b-a)/2,xx=x(new Date(d.ts*1000));
    return `M${xx},${a} A${r},${r} 0 0 ${b>a?1:0} ${xx},${b}`;});
arcs.append("title").text(d=>`${d.s} -> ${d.t}\\n${d.n} flows${d.f?" (detector flagged)":""}`);
const sel=new Set();
function paint(){
  const on=sel.size>0, act=d=>!on||sel.has(d.s)||sel.has(d.t);
  arcs.attr("opacity",d=>act(d)?.85:.05)
      .attr("stroke",d=>on&&act(d)?"#ff3860":(d.f?"#ff9f1c":"#4cc9f0"));
  labels.attr("fill",d=>sel.has(d)?"#ff3860":"#ddd")
        .attr("font-weight",d=>sel.has(d)?"bold":"normal")
        .attr("opacity",d=>!on||sel.has(d)?1:.45);
  info.text(on?`${[...sel].join(" , ")} | ${D.arcs.filter(act).length} arcs`:"Click a host or arc. Click empty space to clear.");
}
labels.on("click",(e,d)=>{e.stopPropagation();const same=sel.size===1&&sel.has(d);sel.clear();if(!same)sel.add(d);paint();});
arcs.on("click",(e,d)=>{e.stopPropagation();sel.clear();sel.add(d.s);sel.add(d.t);paint();});
svg.on("click",()=>{sel.clear();paint();});
paint();
</script>
"""


@st.cache_data(show_spinner="Building arcs...")
def _arcs(db, hosts, slot):
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    ph = ",".join("?" * len(hosts))
    df = pd.read_sql_query(
        f"SELECT src_ip s, dst_ip t, CAST(first_ts/{slot} AS INTEGER)*{slot} ts, COUNT(*) n "
        f"FROM flows WHERE src_ip IN ({ph}) AND dst_ip IN ({ph}) GROUP BY s, t, ts",
        c, params=list(hosts) * 2)
    fl = pd.read_sql_query(
        f"SELECT src_ip s, dst_ip t FROM edges WHERE detector_flag=1 "
        f"AND src_ip IN ({ph}) AND dst_ip IN ({ph})", c, params=list(hosts) * 2)
    c.close()
    flagged = set(zip(fl.s, fl.t))
    df["f"] = [(a, b) in flagged for a, b in zip(df.s, df.t)]
    return df


def timearcs(conn, db_path):
    st.subheader("TimeArcs")
    mode = st.radio("Hosts", ["Detector-flagged", "Top anomaly_score"], horizontal=True, key="ta_m")
    n = st.slider("Hosts", 10, 60, 30, key="ta_n")
    slot = st.select_slider("Slice (seconds)", [10, 30, 60, 120], 60, key="ta_s")
    where = "WHERE detector_flag=1 " if mode.startswith("Det") else ""
    hosts = pd.read_sql_query(
        f"SELECT ip FROM hosts {where}ORDER BY anomaly_score DESC LIMIT ?",
        conn, params=(n,))["ip"].tolist()
    if len(hosts) < 2:
        st.info("Not enough hosts. Detector data may be missing; try Top anomaly_score.")
        return
    df = _arcs(db_path, tuple(hosts), slot)
    if df.empty:
        st.info("No flows between these hosts. Increase the host count.")
        return
    first = pd.concat([df.groupby("s").ts.min(), df.groupby("t").ts.min()]).groupby(level=0).min()
    hosts = sorted(set(df.s) | set(df.t), key=lambda h: first.get(h, 0))
    data = {"hosts": hosts, "t0": float(df.ts.min()), "t1": float(df.ts.max() + slot),
            "arcs": df.to_dict("records")}
    _render(TIMEARCS, data, len(hosts) * 18 + 60)
    st.caption("One arc per host pair per slice. Orange = detector-flagged edge. Row order = first activity.")


# --------------------------------------------------------------- StoryFlow
STORYFLOW = """
<div id="c"></div><script>
const D=__DATA__, cw=170, rh=16, m={l:30,t:60};
const maxN=d3.max(D.regions,r=>r.hosts.length)||1;
const W=m.l+cw*D.regions.length+120, H=m.t+maxN*rh+60;
const svg=d3.select("#c").append("svg").attr("width",W).attr("height",H);
const info=svg.append("text").attr("x",6).attr("y",12).attr("fill","#ddd");
const col=d3.scaleOrdinal(d3.schemeTableau10).domain(D.tracked);
const order=new Map(D.tracked.map((h,i)=>[h,i]));
const pos={};
const regG=svg.selectAll("g.reg").data(D.regions).join("g").attr("class","reg").style("cursor","pointer");
regG.each((r,i)=>{
  [...r.hosts].sort((a,b)=>order.get(a)-order.get(b))
    .forEach((h,j)=>{(pos[h]=pos[h]||[]).push({h,i,x:m.l+i*cw+60,y:m.t+j*rh+rh/2});});
});
regG.append("rect").attr("x",(r,i)=>m.l+i*cw+40).attr("y",m.t-4).attr("width",40)
  .attr("height",r=>r.hosts.length*rh+8).attr("rx",6).attr("fill","#222").attr("stroke","#555");
regG.append("text").attr("x",(r,i)=>m.l+i*cw+60).attr("y",m.t-30).attr("text-anchor","middle")
  .attr("fill","#fff").text(r=>r.type);
regG.append("text").attr("x",(r,i)=>m.l+i*cw+60).attr("y",m.t-18).attr("text-anchor","middle")
  .attr("fill","#999").text(r=>r.when+"  ("+r.n+" hosts)");
const line=d3.line().curve(d3.curveMonotoneX);
const hostG=svg.selectAll("g.h").data(Object.keys(pos)).join("g").attr("class","h").style("cursor","pointer");
hostG.each(h=>pos[h].sort((a,b)=>a.i-b.i));
hostG.append("path").attr("d",h=>line(pos[h].map(q=>[q.x,q.y]))).attr("fill","none")
  .attr("stroke",h=>col(h)).attr("stroke-width",2);
hostG.append("path").attr("d",h=>line(pos[h].map(q=>[q.x,q.y]))).attr("fill","none")
  .attr("stroke","transparent").attr("stroke-width",10);
hostG.selectAll("circle").data(h=>pos[h]).join("circle").attr("cx",q=>q.x).attr("cy",q=>q.y)
  .attr("r",3.5).attr("fill",q=>col(q.h)).append("title").text(q=>q.h);
const lab=hostG.append("text").attr("x",h=>pos[h][pos[h].length-1].x+10)
  .attr("y",h=>pos[h][pos[h].length-1].y+3).text(h=>h);
const sel=new Set();
function paint(){
  const on=sel.size>0;
  hostG.attr("opacity",h=>!on||sel.has(h)?1:.1);
  hostG.select("path").attr("stroke-width",h=>on&&sel.has(h)?4:2);
  lab.attr("fill",h=>on&&sel.has(h)?"#ff3860":col(h));
  info.text(on?`${sel.size} host${sel.size>1?"s":""}: ${[...sel].slice(0,4).join(" , ")}${sel.size>4?" ...":""}`
              :"Click a host or stage. Click empty space to clear.");
}
hostG.on("click",(e,h)=>{e.stopPropagation();const same=sel.size===1&&sel.has(h);sel.clear();if(!same)sel.add(h);paint();});
regG.on("click",(e,r)=>{e.stopPropagation();sel.clear();r.hosts.forEach(h=>sel.add(h));paint();});
svg.on("click",()=>{sel.clear();paint();});
paint();
</script>
"""


def storyflow(conn, db_path):
    st.subheader("StoryFlow (detector attack stages)")
    k = st.slider("Max tracked hosts", 5, 40, 20, key="sf_k")
    r = pd.read_sql_query(
        "SELECT attack_type, known_name, t_min, t_max, ips_json FROM detector_regions "
        "ORDER BY t_min", conn)
    if r.empty:
        st.info("detector_regions is empty. The pipeline needs NETWORK_DETECTOR_RESULTS/detector-results.json.")
        return
    r["ips"] = r.ips_json.apply(lambda s: json.loads(s) if s else [])
    counts = pd.Series([ip for l in r.ips for ip in l]).value_counts()
    tracked = counts[counts >= 2].head(k).index.tolist()
    if not tracked:
        st.info("No host appears in more than one detector region, so there are no carry-over lines.")
        return
    ts = set(tracked)
    regions = [{
        "type": row.known_name or row.attack_type or "?",
        "when": pd.to_datetime(row.t_min, unit="s", utc=True).strftime("%H:%M"),
        "n": len(row.ips),
        "hosts": [h for h in row.ips if h in ts],
    } for row in r.itertuples()]
    regions = [x for x in regions if x["hosts"]]
    h = max(len(x["hosts"]) for x in regions) * 16 + 140
    _render(STORYFLOW, {"regions": regions, "tracked": tracked}, h)
    st.caption("Columns = detector regions in time order. A line follows a host from stage to stage. Only hosts in 2+ regions are drawn.")


# ------------------------------------------------------------------- stubs
# ------------------------------------------------------- shared edge helpers
def _edges(conn, n, flagged_only):
    having = " HAVING MAX(detector_flag)=1" if flagged_only else ""
    return pd.read_sql_query(
        "SELECT src_ip s, dst_ip t, SUM(bytes) b, SUM(flow_count) n, MAX(detector_flag) f "
        f"FROM edges GROUP BY s, t{having} ORDER BY b DESC LIMIT ?", conn, params=(n,))


def _host_info(conn):
    h = pd.read_sql_query("SELECT ip, is_internal, detector_flag FROM hosts", conn)
    return {r.ip: (int(r.is_internal), int(r.detector_flag)) for r in h.itertuples()}


# --------------------------------------------------------------- Force Graph
FORCE = """
<div id="c"></div><script>
const D=__DATA__, W=1100, H=650;
const sid=l=>l.source.id??l.source, tid=l=>l.target.id??l.target;
const nb=new Map(D.nodes.map(n=>[n.id,new Set([n.id])]));
D.links.forEach(l=>{nb.get(sid(l)).add(tid(l)); nb.get(tid(l)).add(sid(l));});
const svg=d3.select("#c").append("svg").attr("width",W).attr("height",H);
const g=svg.append("g");
svg.call(d3.zoom().scaleExtent([0.2,6]).on("zoom",e=>g.attr("transform",e.transform)));
const info=svg.append("text").attr("x",10).attr("y",18).attr("fill","#ddd");
const color=d=>d.f?"#ff9f1c":(d.i?"#4cc9f0":"#b5b5b5");
const link=g.append("g").selectAll("line").data(D.links).join("line")
  .attr("stroke",d=>d.f?"#ff9f1c":"#667").attr("stroke-opacity",.45)
  .attr("stroke-width",d=>Math.min(4,0.5+Math.log10(d.n+1)));
link.append("title").text(d=>`${sid(d)} -> ${tid(d)} | ${d.n} flows`);
const node=g.append("g").selectAll("path").data(D.nodes).join("path")
  .style("cursor","pointer")
  .attr("d",d=>d3.symbol().type(d.i?d3.symbolSquare:d3.symbolCircle).size(40+18*d.deg)())
  .attr("fill",color).attr("stroke","#111")
  .call(d3.drag()
    .on("start",(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
    .on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y;})
    .on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
node.append("title").text(d=>`${d.id} | ${d.i?"internal":"external"} | ${d.deg} links${d.f?" | detector flagged":""}`);
let cur=null;
function paint(){
  node.attr("opacity",d=>!cur||nb.get(cur).has(d.id)?1:.08)
      .attr("stroke",d=>d.id===cur?"#fff":"#111").attr("stroke-width",d=>d.id===cur?3:1);
  link.attr("stroke-opacity",d=>!cur||sid(d)===cur||tid(d)===cur?.9:.03);
  info.text(cur?`${cur} | ${nb.get(cur).size-1} neighbors`:"Click a node. Click empty space to clear.");
}
node.on("click",(e,d)=>{e.stopPropagation();cur=cur===d.id?null:d.id;paint();});
svg.on("click",()=>{cur=null;paint();});
const sim=d3.forceSimulation(D.nodes)
  .force("link",d3.forceLink(D.links).id(d=>d.id).distance(40))
  .force("charge",d3.forceManyBody().strength(-70))
  .force("center",d3.forceCenter(W/2,H/2))
  .force("collide",d3.forceCollide(8))
  .on("tick",()=>{
    link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
    node.attr("transform",d=>`translate(${d.x},${d.y})`);
  });
paint();
</script>
"""


def force_graph(conn, db_path):
    st.subheader("Force Graph")
    n = st.slider("Edges", 50, 1000, 250, key="fg_n")
    flagged = st.checkbox("Detector-flagged edges only", key="fg_f")
    e = _edges(conn, n, flagged)
    if e.empty:
        st.info("No edges. Detector data may be missing; uncheck the filter.")
        return
    info = _host_info(conn)
    deg = pd.concat([e.s, e.t]).value_counts()
    flagged_ips = set(e[e.f == 1].s) | set(e[e.f == 1].t)
    nodes = [{"id": ip, "i": info.get(ip, (0, 0))[0],
              "f": int(info.get(ip, (0, 0))[1] or ip in flagged_ips),
              "deg": int(d)} for ip, d in deg.items()]
    links = [{"source": r.s, "target": r.t, "n": int(r.n), "f": int(r.f)} for r in e.itertuples()]
    _render(FORCE, {"nodes": nodes, "links": links}, 670)
    st.caption("Square = internal host, circle = external. Orange = detector-flagged. "
               "Size = number of links. Drag nodes, scroll to zoom.")


# ------------------------------------------------------------------ NodeTrix
NODETRIX = """
<div id="c"></div><script>
const D=__DATA__, cs=D.cell, m={l:140,t:140};
const N=D.hosts.length, W=m.l+N*cs+20, H=m.t+N*cs+20;
const svg=d3.select("#c").append("svg").attr("width",W).attr("height",H);
const idx=new Map(D.hosts.map((h,i)=>[h.ip,i]));
const mx=d3.max(D.cells,d=>Math.log1p(d.n))||1;
const col=d3.scaleSequential(d3.interpolateYlOrRd).domain([0,mx]);
const info=svg.append("text").attr("x",6).attr("y",14).attr("fill","#ddd");
svg.append("rect").attr("x",m.l).attr("y",m.t).attr("width",N*cs).attr("height",N*cs)
  .attr("fill","#1b1b1b").attr("stroke","#444");
const fs=Math.min(10,cs-2);
const rows=svg.selectAll(".r").data(D.hosts).join("text").style("cursor","pointer")
  .attr("x",m.l-4).attr("y",(d,i)=>m.t+i*cs+cs*0.7).attr("text-anchor","end").attr("font-size",fs).text(d=>d.ip);
const cols=svg.selectAll(".c").data(D.hosts).join("text").style("cursor","pointer")
  .attr("transform",(d,i)=>`translate(${m.l+i*cs+cs*0.7},${m.t-4}) rotate(-90)`)
  .attr("font-size",fs).text(d=>d.ip);
const cells=svg.selectAll("rect.cell").data(D.cells).join("rect").style("cursor","pointer")
  .attr("x",d=>m.l+idx.get(d.t)*cs).attr("y",d=>m.t+idx.get(d.s)*cs)
  .attr("width",cs-1).attr("height",cs-1).attr("fill",d=>col(Math.log1p(d.n)));
cells.append("title").text(d=>`${d.s} -> ${d.t} | ${d.n} flows${d.f?" | detector flagged":""}`);
const sel=new Set();
function paint(){
  const on=sel.size>0, act=d=>!on||sel.has(d.s)||sel.has(d.t);
  cells.attr("opacity",d=>act(d)?1:.07)
       .attr("stroke",d=>on&&act(d)?"#fff":(d.f?"#4cc9f0":"none")).attr("stroke-width",d=>on&&act(d)?1:1.5);
  [rows,cols].forEach(s=>s.attr("fill",d=>sel.has(d.ip)?"#ff3860":(d.i?"#4cc9f0":"#ddd"))
    .attr("font-weight",d=>sel.has(d.ip)?"bold":"normal").attr("opacity",d=>!on||sel.has(d.ip)?1:.5));
  info.text(on?`${[...sel].join(" , ")} | ${D.cells.filter(act).length} cells`:"Click a label or cell. Click empty space to clear.");
}
function pick(e,ip){e.stopPropagation();const same=sel.size===1&&sel.has(ip);sel.clear();if(!same)sel.add(ip);paint();}
rows.on("click",(e,d)=>pick(e,d.ip)); cols.on("click",(e,d)=>pick(e,d.ip));
cells.on("click",(e,d)=>{e.stopPropagation();sel.clear();sel.add(d.s);sel.add(d.t);paint();});
svg.on("click",()=>{sel.clear();paint();});
paint();
</script>
"""


def nodetrix(conn, db_path):
    st.subheader("NodeTrix-style adjacency matrix")
    n = st.slider("Hosts", 10, 80, 30, key="nt_n")
    order = st.radio("Order by", ["Traffic", "Anomaly score", "Internal first"],
                     horizontal=True, key="nt_o")
    sql = {"Traffic": "(bytes_in+bytes_out) DESC",
           "Anomaly score": "anomaly_score DESC",
           "Internal first": "is_internal DESC, (bytes_in+bytes_out) DESC"}[order]
    h = pd.read_sql_query(f"SELECT ip, is_internal FROM hosts ORDER BY {sql} LIMIT ?",
                          conn, params=(n,))
    ips = h.ip.tolist()
    if len(ips) < 2:
        st.info("Not enough hosts.")
        return
    ph = ",".join("?" * len(ips))
    e = pd.read_sql_query(
        f"SELECT src_ip s, dst_ip t, SUM(flow_count) n, MAX(detector_flag) f FROM edges "
        f"WHERE src_ip IN ({ph}) AND dst_ip IN ({ph}) GROUP BY s, t",
        conn, params=ips * 2)
    if e.empty:
        st.info("No edges among these hosts. Increase the host count.")
        return
    cell = 18 if len(ips) <= 40 else 12
    data = {"hosts": [{"ip": r.ip, "i": int(r.is_internal)} for r in h.itertuples()],
            "cells": [{"s": r.s, "t": r.t, "n": int(r.n), "f": int(r.f)} for r in e.itertuples()],
            "cell": cell}
    _render(NODETRIX, data, 180 + len(ips) * cell)
    st.caption("Rows = source, columns = destination. Color = flow count (log). "
               "Cyan outline = detector-flagged. A filled row is one host reaching many, the scan shape. "
               "Blue labels = internal hosts.")


# ------------------------------------------------------------------ BioFabric
BIOFABRIC = """
<div id="c"></div><script>
const D=__DATA__, rh=14, cw=9, m={l:140,t:28};
const adj=new Map();
D.edges.forEach(e=>{
  if(!adj.has(e.s))adj.set(e.s,[]); if(!adj.has(e.t))adj.set(e.t,[]);
  adj.get(e.s).push(e.t); adj.get(e.t).push(e.s);
});
const byDeg=[...adj.keys()].sort((a,b)=>adj.get(b).length-adj.get(a).length);
const order=[], seen=new Set();
byDeg.forEach(s=>{ if(seen.has(s))return; const q=[s]; seen.add(s);
  while(q.length){const u=q.shift(); order.push(u);
    adj.get(u).slice().sort((a,b)=>adj.get(b).length-adj.get(a).length)
      .forEach(v=>{if(!seen.has(v)){seen.add(v);q.push(v);}});}});
const row=new Map(order.map((h,i)=>[h,i]));
const edges=D.edges.map(e=>({...e,a:Math.min(row.get(e.s),row.get(e.t)),b:Math.max(row.get(e.s),row.get(e.t))}))
  .sort((x,y)=>x.a-y.a||x.b-y.b);
const W=m.l+edges.length*cw+20, H=m.t+order.length*rh+20;
const svg=d3.select("#c").append("svg").attr("width",W).attr("height",H);
const info=svg.append("text").attr("x",6).attr("y",14).attr("fill","#ddd");
const ry=h=>m.t+row.get(h)*rh+rh/2, ex=i=>m.l+i*cw+cw/4;
const span=new Map();
edges.forEach((e,i)=>{[e.s,e.t].forEach(h=>{const s=span.get(h)||[i,i];s[0]=Math.min(s[0],i);s[1]=Math.max(s[1],i);span.set(h,s);});});
const hostG=svg.selectAll("g.h").data(order).join("g").attr("class","h").style("cursor","pointer");
hostG.append("line").attr("x1",h=>m.l+span.get(h)[0]*cw).attr("x2",h=>m.l+span.get(h)[1]*cw+cw/2)
  .attr("y1",ry).attr("y2",ry).attr("stroke","#777");
hostG.append("line").attr("x1",h=>m.l+span.get(h)[0]*cw).attr("x2",h=>m.l+span.get(h)[1]*cw+cw/2)
  .attr("y1",ry).attr("y2",ry).attr("stroke","transparent").attr("stroke-width",10);
hostG.append("text").attr("x",h=>m.l+span.get(h)[0]*cw-4).attr("y",h=>ry(h)+3)
  .attr("text-anchor","end").attr("font-size",9).text(h=>h);
const edgeG=svg.selectAll("g.e").data(edges).join("g").attr("class","e").style("cursor","pointer");
edgeG.append("line").attr("x1",(e,i)=>ex(i)).attr("x2",(e,i)=>ex(i))
  .attr("y1",e=>ry(e.s)).attr("y2",e=>ry(e.t)).attr("stroke",e=>e.f?"#ff9f1c":"#4cc9f0").attr("stroke-width",1.5);
edgeG.append("line").attr("x1",(e,i)=>ex(i)).attr("x2",(e,i)=>ex(i))
  .attr("y1",e=>ry(e.s)).attr("y2",e=>ry(e.t)).attr("stroke","transparent").attr("stroke-width",7);
edgeG.append("circle").attr("cx",(e,i)=>ex(i)).attr("cy",e=>ry(e.s)).attr("r",2.5)
  .attr("fill",e=>e.f?"#ff9f1c":"#4cc9f0");
edgeG.append("title").text(e=>`${e.s} -> ${e.t} | ${e.n} flows${e.f?" | detector flagged":""}`);
const sel=new Set();
function paint(){
  const on=sel.size>0, act=e=>!on||sel.has(e.s)||sel.has(e.t);
  const nbr=new Set(); edges.forEach(e=>{if(act(e)){nbr.add(e.s);nbr.add(e.t);}});
  edgeG.attr("opacity",e=>act(e)?1:.06);
  hostG.attr("opacity",h=>!on||nbr.has(h)?1:.12);
  hostG.select("text").attr("fill",h=>sel.has(h)?"#ff3860":(D.internal[h]?"#4cc9f0":"#ddd"))
    .attr("font-weight",h=>sel.has(h)?"bold":"normal");
  info.text(on?`${[...sel].join(" , ")} | ${edges.filter(act).length} edges`:"Click a host or edge. Click empty space to clear.");
}
hostG.on("click",(ev,h)=>{ev.stopPropagation();const same=sel.size===1&&sel.has(h);sel.clear();if(!same)sel.add(h);paint();});
edgeG.on("click",(ev,e)=>{ev.stopPropagation();sel.clear();sel.add(e.s);sel.add(e.t);paint();});
svg.on("click",()=>{sel.clear();paint();});
paint();
</script>
"""


def biofabric(conn, db_path):
    st.subheader("BioFabric")
    n = st.slider("Edges", 30, 400, 120, key="bf_n")
    flagged = st.checkbox("Detector-flagged edges only", key="bf_f")
    e = _edges(conn, n, flagged)
    if e.empty:
        st.info("No edges. Detector data may be missing; uncheck the filter.")
        return
    info = _host_info(conn)
    ips = set(e.s) | set(e.t)
    data = {"edges": [{"s": r.s, "t": r.t, "n": int(r.n), "f": int(r.f)} for r in e.itertuples()],
            "internal": {ip: info.get(ip, (0, 0))[0] for ip in ips}}
    _render(BIOFABRIC, data, len(ips) * 14 + 60)
    st.caption("Each horizontal line is a host, each vertical line is one edge between two hosts "
               "(dot = source). Hosts are ordered by breadth-first search from the busiest host. "
               "Orange = detector-flagged. Blue labels = internal hosts.")

VIEWS = {
    "TimeArcs": timearcs,
    "StoryFlow": storyflow,
    "Force Graph": force_graph,
    "NodeTrix": nodetrix,
    "BioFabric": biofabric,
}


def show_graphs(database_path):
    db = Path(database_path)
    if not db.is_file():
        st.info("Database file not found. Set NETWORK_DB_PATH to the SQLite file location.")
        return
    view = st.radio("View", list(VIEWS), horizontal=True)
    path = db.resolve().as_posix()
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
        VIEWS[view](conn, path)
