# The Witness certificate
A Witness session over a GitHub Actions workflow emits a
certificate: a JSON object carrying the sha256 of the exact
source file, the exact count of admissible schedules the recorded
dependencies permit, and a list of artifacts. Artifact types:
a verdict (PROVEN_YES, PROVEN_NO with a witness chain of recorded
dependencies, or UNRESOLVED with the exact proportion), an
exhibit (a complete valid schedule demonstrating one branch of an
unresolved ordering), and a what-if (the exact count after a
proposed dependency). The certificate is sealed by a digest over
its own contents.
Verification comes in two modes. Light mode, the script in
tools/witness_verify_light.py, checks the source digest, every
chain edge against the file, and every exhibit's validity and
direction, in linear time, with no reconstruction of the space.
Full mode reconstructs the space and recomputes every count and
proportion; it is available under evaluation terms.
Patents pending GB2618664.3 and GB2619009.0. Contact:
arcifact.io.
