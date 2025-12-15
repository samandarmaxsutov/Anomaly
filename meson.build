project('l2fwd', 'c',
  version: '0.1.0',
  default_options: [
    'buildtype=release',
    'c_std=c11',
    'warning_level=2',
  ],
)

dep_json = dependency('json-c', required: true)
dpdk_dep = dependency('libdpdk', required: true)
dep_curl = dependency('libcurl', required: true)
dep_threads = dependency('threads')

add_project_arguments('-D_GNU_SOURCE', language: 'c')
add_project_arguments('-march=native', '-O3', '-funroll-loops', language: 'c')

src = [
  'main.c',
  'l2fwd_ddos_collector.c',
  ]

executable('l2fwd',
  sources: src,
  # FIX: Added ssl_dep to the list below
  dependencies: [dpdk_dep, dep_json, dep_curl, dep_threads], 
  link_args: ['-lm'],
  install: true,
)