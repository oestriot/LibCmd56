# Cmd56

a library to implement gamecart & vita authentication

PROGRESS:

- Gamecart side fully implemented
- Vita side not yet implemented


```

gamecart side:

include "cmd56/gc.h"

void gc_cmd56_init(gc_cmd56_state* state, char* rif_part, char* klic_part);
void gc_cmd56_update_keyid(gc_cmd56_state* state, uint16_t key_id);
void gc_cmd56_update_keys(gc_cmd56_state* state, char* rif_part, char* klic_part);
void gc_cmd56_run_in_place(gc_cmd56_state* state, char* buffer);
void gc_cmd56_run(gc_cmd56_state* state, char* buffer, char* response);
```
