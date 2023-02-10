#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DMA_HOST_MEMORY', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

dependencies = []
# Required for all DOCA programs
dependencies += dependency('doca-common')
# Library needed for this sample
dependencies += dependency('doca-dma')
# Library used by the main() function
dependencies += dependency('doca-argp')
# Library used by the main() function
dependencies += dependency('libbsd')

srcs = [
	# The sample itself
	'dma.c',
	# Common code for the DOCA library samples
	'/opt/mellanox/doca/samples/doca_dma/dma_common.c',
	# Common code for all DOCA samples
	'/opt/mellanox/doca/samples/common.c',
	# Common code for all DOCA applications
	'/opt/mellanox/doca/applications/common/src/utils.c',
	# Common code for all DOCA applications
        '../../../utils/dma_exchange.c',
]

inc_dirs  = []
# Common DOCA library logic
inc_dirs += include_directories('/opt/mellanox/doca/samples/doca_dma')
# Common DOCA logic (samples)
inc_dirs += include_directories('/opt/mellanox/doca/samples')
# Common DOCA logic
inc_dirs += include_directories('/opt/mellanox/doca')
# Common DOCA logic (applications)
inc_dirs += include_directories('/opt/mellanox/doca/applications/common/src')

executable('dma', srcs,
	dependencies : dependencies,
	include_directories: inc_dirs,
	install: false)
