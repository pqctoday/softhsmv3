// softhsm_pre.js — Emscripten pre-JS shim for SoftHSMv3 WASM
//
// Loaded by emcc --pre-js before the WASM module starts executing.
// Pre-populates the Emscripten MEMFS virtual filesystem with the directory
// structure and default softhsmv3.conf that C_Initialize(NULL) expects.
//
// Callers can customize token storage after module load:
//   - Node.js: use FS.mount(NODEFS, { root: '/path/on/host' }, '/var/lib/softhsmv3/tokens')
//   - Browser: use FS.mount(IDBFS, {}, '/var/lib/softhsmv3/tokens') for persistence
//   - Any: write a custom config to /etc/softhsmv3.conf before calling C_Initialize

var Module = Module || {};
Module['preRun'] = Module['preRun'] || [];
Module['preRun'].push(function() {
    // Create the required directory tree in MEMFS
    // Wrapped in try/catch because directories may already exist if the caller
    // has pre-mounted a filesystem layer
    try { FS.mkdir('/etc'); } catch(e) {}
    try { FS.mkdir('/var'); } catch(e) {}
    try { FS.mkdir('/var/lib'); } catch(e) {}
    try { FS.mkdir('/var/lib/softhsmv3'); } catch(e) {}
    try { FS.mkdir('/var/lib/softhsmv3/tokens'); } catch(e) {}

    // Write the default softhsmv3.conf
    // C_Initialize(NULL) reads DEFAULT_SOFTHSM2_CONF which is compiled-in as
    // /etc/softhsmv3.conf (set by DEFAULT_SOFTHSM2_CONF cmake option)
    FS.writeFile('/etc/softhsmv3.conf',
        'directories.tokendir = /var/lib/softhsmv3/tokens/\n' +
        'objectstore.backend = file\n' +
        'log.level = ERROR\n'
    );
});
