# Network Traffic Explorer

## What this project is

Network Traffic Explorer turns a raw packet capture into a picture that a person
can investigate, and puts an AI analyst next to that picture. The two work on
the same view of the same data. You choose what to look at. The assistant reads
the detail of what you chose and answers questions about it. The goal is to find
the attacks that are hidden in ordinary traffic, and to do it without reading a
single packet payload.

The project has two parts. A Python pipeline reads the capture files and builds
connection statistics in a SQLite database. A browser application draws those
statistics and hosts the assistant. This document introduces the whole project.
The pipeline is the part that produces the data, and it has its own guide.

## The data

The dataset is the CDX 2009 exercise capture. The default run covers 90 minutes
of one day, 2009-11-03. It holds about 3.6 million flows between about 40,000
addresses. A flow is one conversation between two addresses on two ports.

Nothing in the application reads packet contents. Every statement comes from the
shape of the traffic: who contacted whom, at what time, how much data moved, on
which port, and how each connection ended. Three endings look different in the data: a connection that closes
normally, a connection that is refused, and a connection that never completes
its handshake. That difference carries most of the evidence.

The exercise also ships a ground-truth catalogue of 8,223 attack events. The
application treats that catalogue as an answer key, not as an input. The
assistant runs without it by default. See "The assistant" below.

## How an investigation works

The loop has four steps, and you repeat them.

1. You look at a view and find something that stands out.
2. You select the hosts or the time window that interest you.
3. You ask the assistant a question. Your selection is the scope of the answer.
4. The assistant answers, and writes its answer back onto the plot.

Step 4 is what makes the loop work. The assistant does not only reply with text.
It selects nodes, opens a time view, spotlights hosts, draws a chart, and writes
role names beside the rows of the timeline. A claim in a chat panel is hard to
check against a plot. A claim drawn on the plot is easy to check.

## The views

Each view answers a different question about the same graph.

- Force Graph: who talks to whom. Hosts are nodes, and connections are links.
  A square is a machine inside the network, and a circle is a machine outside
  it. Node size follows traffic volume. This view shows structure and groups.
- TimeArcs: when it happened. Every host is a row, and every connection is an
  arc placed at the moment it started. Bursts, waves, and sequences that the
  Force Graph hides become obvious here.
- NodeTrix: an adjacency matrix of the busiest hosts. A filled row means one
  host reached many hosts, which is the shape of a scan. This view stays
  readable where the Force Graph turns into a hairball.
- BioFabric: hosts and connections as parallel lines, for dense neighborhoods.
- StoryFlow: the attack stages over time, with the hosts that carry from one
  stage to the next.

## Signals and filters

The pipeline derives twelve behavioral signals for every host. Six of them are:

- fan-out, which counts the distinct destinations a host contacted
- half-open connections, which are handshakes that got no answer
- peak connection rate
- retransmits
- reset rate
- handshake round-trip time

An anomaly score summarizes the twelve. It is the largest z-score across all
signals, measured against the median so that a few extreme hosts cannot move
the baseline. If a host stands out on any one behavior, it scores high.

Each signal has a slider, and the sliders combine with AND. Three sliders reduce
40,000 hosts to a handful in a few seconds. You can also color the nodes by any
signal, and plot a signal over time as a small chart on the node itself.

## Pattern search

Filters find hosts. Pattern search finds shapes that involve several hosts and
the order in which they act. Eight templates ship with the application. Among them are a beacon-to-payload
hand-off, a horizontal scan, a fan-in convergence, a connection flood, and a
byte-asymmetry pattern for data theft.

A match is not an answer. It is a place to start looking.

## The assistant

The assistant is Claude, running in a FastAPI service beside the database. It
has around thirty tools. With them it can:

- describe a host, an edge, or your current selection
- run a read-only SQL query against the flows table
- compare two time windows, and find the time clusters in a view
- build a role table for every host in scope
- draw a chart from up to 20,000 rows without spending context on them
- act on the display: select nodes, focus a time window, spotlight hosts, and
  open the timeline on a set of hosts

Two properties matter more than the tool count.

The assistant shares your scope. What you select is what it reads. This is how
you steer it, and it is also how you catch it being wrong: when an answer is
thin, the usual cause is that the scope was too narrow, and you widen it and ask
again.

The assistant does not see the ground truth. The default mode strips the answer-key columns from every tool result. It also
blocks the ground-truth tables in SQL and withholds the label tools. The assistant judges the traffic on
the same evidence you have. When its account and the catalogue agree afterwards,
that agreement means something. A second mode turns the catalogue on, for work
on the labels themselves.

## Two investigations

These two cases are worked examples, and both are recorded in full.

The malware flood. Pattern search returns a beacon-to-payload hand-off. In the
timeline, one external host contacts ten internal machines. A second external
host follows about ten seconds later. A few minutes after that, every one of
those machines throws thousands of connections at a single target. Every one of
those connections is reset during the handshake. One machine took the payload and never joined
the flood. The assistant reads the first external host as a command-and-control
check-in and the second as a staging server. It leaves the machine that never
fired unlabelled.

The spambot campaign. Seven hosts stay active through all four phases of the
capture while the machines around them rotate. That marks the seven as
infrastructure rather than victims. The role table then names hosts that no
human had connected to the case. One of them is an external receiver that does
nothing except accept a 53 MB upload on a remote-administration port. The
upload happens while the loud traffic is at its peak. The evidence establishes that the transfer
coincides with the noise. It does not establish that the noise was created to
hide the transfer.

Both cases show the same division of work. The person sees the shape and sets
the scope. The assistant reads the detail and names the roles. In the first
case, the assistant missed the beacon until the scope was widened. In the second
case, the person missed the receiver until the assistant tabulated every host.

## Where the pipeline fits

The pipeline is the first half of the project. It downloads the capture files and
parses them into flows. It derives the host and host-pair statistics and the
twelve signals. It labels the traffic against the ground-truth catalogue, and
exports the JSON that the browser application reads. It also audits itself, because a
derived source that covers less of the capture than the capture holds makes a
chart go quietly empty.

The pipeline package that accompanies this document contains that half only. Its
`README.md` states what the 90-minute run needs and how to run it.
