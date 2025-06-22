# Work Dispatching

An introductory example that demonstrates dispatching work to processing threads, removing subscription processing off of the critical path.

Specification: 
- Per rx core routing to worker threads
- Dedicated worker threads per callback
