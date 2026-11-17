# Gold VM Manager API / UI contract

Independent local app, NOT the DSH UI. Python stdlib backend with static HTML/CSS/JS frontend; no CDN/runtime packages.
Base URL is same-origin on 127.0.0.1, planned port18765. UI gets auth token from location.hash `#token=...`; remove fragment with history.replaceState after reading and keep token in sessionStorage for reload. All /api calls except health require `Authorization: Bearer <token>`. Mutations POST application/json, same-origin Origin required (browser sends it). No secrets/credentials in API responses or console.

Success responses: `{ok:true,...fields}`. Error: `{ok:false,error:"Chinese message",code:"machine_code"}`, HTTP400/401/403/409/500.

GET /api/state:
```
{ok:true, app:{name:"Gold VM Manager",version:"1.0.0"},
 host:{cpu_count:10,memory_gib:64,free_disk_gib:180},
 vms:[{id:"gold",name:"gold",state:"stopped"|"running"|"suspended"|"missing",cpu:4,memory_gib:6,disk_gb:50,allocated_gb:31,
 network:{protected:true,blocked:false,management_enabled:false},
 shares:[{id:"uuid",name:"project",path:"/absolute/host/path",read_only:false,enabled:true}],
 active_shares:[],pending_share_changes:false,pause_supported:true,
 busy:false,operation:null,last_error:null,last_event:null}],
 events:[{time:"ISO",vm:"gold",action:"start",message:"已请求启动",level:"info"}],
 capabilities:{native_picker:true}}
```
IDs come from the controller's current legacy mapping plus managed registry; the example names above are illustrative, not the complete allowed list. Shares are desired config; active_shares reflect last launch. stopped VM active_shares=[]; paused VM continues prior launch shares. Pending changes apply ONLY next cold start, not live/savedstate. Pause is unavailable while active shares or the generated setup share exist. network.blocked shows existing drop_proxy but UI MUST NOT add an unblock control or silently change it. allocated_gb is an allocation estimate; shared APFS extents mean it must not be summed as unique physical usage. The main panel does not display the former verbose disk-allocation paragraph.

POST /api/vms/<id>/action body `{action:"start"|"pause"|"shutdown"|"force-stop"|"discard-state"|"focus", confirm_name?:"gold"}` -> {ok:true,message:"..."}. start is asynchronous return202 and UI pollsstate. shutdown sends guest power-button request, may require macOS confirmation INSIDE guest; NOT guaranteed shutdown. force-stop and discard-state require modal + exact typedVMname; they can lose unsaved data. Never auto force/discard. `recovery-start` additionally requires the exact VM name, stopped state, and a compatible generated protected launcher; it preserves the network fence and mounts no shares. start while suspended resumes old directory config and pending updates wait for normal shutdown. pause supported only no active shared directories.

POST /api/vms/<id>/shares body `{shares:[{id?:"uuid",name:"project",path:"/host/path",read_only:false,enabled:true}]}` saves desired full list. Backend canonicalizes, validates user-owned existing directory, rejects dangerous roots/private keys/VM images/control files, colon or newline paths incompatible with Tart. Use default readonly false ONLY with explicit warning/consent at Add or access-mode change (checkbox client; backend `acknowledge_write:true` if any RW entries added/new path/changedRO->RW). Disabling/removing needs no destructive physical file action. Does NOT create or delete host dirs. Return {ok:true,shares:[...],pending_share_changes:bool,message:"..."}. No silent restart.

POST /api/pick-directory `{vm:"gold"}` -> {ok:true,path:"/canonical/path"} OR {ok:true,cancelled:true}. Native macOS choose-folder dialog opened ONLY by explicit click; optional manual path works too. Picker can remain pending; HTTPclient needs long timeout. Native picker foreground activation is user-triggered; no admin prompts.

POST /api/reveal-directory `{vm:"gold",share_id:"uuid"}` -> {ok:true} opens Finder for EXISTING configured share only. UI copy command is local Clipboard API on explicitclick, example `cd -- '<path>' && claude`; quote shell path correctly (singlequote replacement). Do NOT auto launch Claude Code or read shared file contents.

POST /api/vms/<id>/delete body `{confirm_name:"exact VM name",acknowledge_erase:true}` queues a dedicated deletion job. Requires the trusted inventory target to be stopped or suspended; it does not stop running VMs. Completion is reported through `build_job`, not inferred from HTTP success. Exact retention and journal semantics: [VM_DELETION.md](<VM_DELETION.md>).

POST /api/build accepts explicit create/rebuild requests, user-selected names/resources, acknowledged setup materials, and additional exact-name/erase confirmation for rebuild. `build_job` reports progress, terminal results, and recovery interlocks; incomplete journals must not be hidden. See [CREATE_REBUILD_GUIDE.md](<CREATE_REBUILD_GUIDE.md>) and current request validation in [manager.py](<manager.py>).

The API does not accept guest account passwords. Retained native first-boot automation code is experimental and paused, not a supported automatic setup endpoint.

Optional GET /api/health is unauthenticated and returns app/version health without private paths. The state example above is abbreviated; current state also includes managed-VM setup/rebuild/recovery capabilities and build_job.

Visual language Chinese; light gray/white surfaces, black text, blue primary controls and clearly outlined red destructive controls. Main operation buttons have at least 44-point height; responsive cards, status chips and per-VM shared-folder list; native directory picker plus manual entry; clear share read-only/readwrite, guest mountpath `/Volumes/My Shared Files/<name>` and host ClaudeCode workflow. Empty state deliberate. Show in-app confirmation dialogs, toast success/errors; avoid alert()/confirm() for main UX. Control busy + client async status polling every3s without overwriting edited form. No mock runtime data in production UI. Data rendered via textContent not unsafeHTML. CSPallows only self; no inline event handlers or externalfonts/scripts. Provide static/index.html, style.css, app.js only in delegated UI scope.
