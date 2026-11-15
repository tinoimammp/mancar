# 4. The agent dials only what its user configured

**Status:** accepted

## Context
A tunnel agent runs inside someone's private network. If the gateway could tell
it where to connect, a compromised or malicious gateway would become a proxy
into that network.

## Decision
Data streams carry only a `tunnel_id`. The agent maps it to the local address the
user passed on the command line (or saved in the config) and refuses ids it did
not register. There is no protocol message that names a destination.

## Consequences
* The trust the user places in the gateway is limited to the traffic of the tunnels they created.
* Features that need dynamic destinations (for example routing by path to several local ports) must be configured on the agent side.
