# SmartPot Orchestrator

This folder has the SmartPot Orchestrator. It is composed by:

- Manager
- Layer4 Responder: a responder that opens TCP connections and saves the first packet with payload in each flow.
- DPI Responder: a responder that forwards traffic to backend systems after performing DPI classification. Flexible selection of the backend is possible using the DPI classification labels.

The SmartPot Orchestrator is configured using the yaml found in the ``etc'' folder.
