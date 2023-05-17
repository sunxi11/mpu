#
# Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#



app_dependencies += dependency('doca-argp')
app_dependencies += dependency('doca-flow')
app_dependencies += dependency('doca-common')

app_srcs = [
	'lthread.c',
	'lthread_sched.c', 
	'lthread_cond.c',
	'lthread_tls.c', 
	'lthread_mutex.c',
	'lthread_diag.c',
	'ctx.c',
	'fasthash.c',
	common_dir_path + '/dpdk_utils.c',
	common_dir_path + '/offload_rules.c',
	common_dir_path + '/utils.c',
]






dirs = ['cm', 'cs','cbf','es','fr','nitro','um', 'skv']
foreach dir : dirs
    my_files = run_command('python3', 'get_files.py', dir)
    my_files = my_files.stdout().strip().split('\n')
    foreach file : my_files
  	executable (file, 
  	app_srcs + ['./'+ dir + '/' + file + '.c'],
  	dependencies : app_dependencies,
  	include_directories : app_inc_dirs,
  	install: install_apps)
   endforeach
endforeach


