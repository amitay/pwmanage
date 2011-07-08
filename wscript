#!/usr/bin/env python
# encoding: utf-8

APPNAME = 'pwmanage'
VERSION = '0.1'

top = '.'
out = 'build'


def options(ctx):
	ctx.load('compiler_c')

def configure(ctx):
	print('	configuring the project in ' + ctx.path.abspath())

	# global definitions
	ctx.define('PWMANAGE_VERSION', VERSION)

	# programs
	ctx.load('compiler_c');
	# ctx.find_program('cc', mandatory=True)

	# libraries
	ctx.check_cfg(package='tdb', uselib_store='TDB', 
			args=['--cflags', '--libs'])
	ctx.check_cfg(package='talloc', uselib_store='TALLOC', 
			args=['--cflags', '--libs'])

	# check for headers
	ctx.check(header_name='time.h')

	# check for functions
	ctx.check_cc(function_name='printf', header_name='stdio.h')
	
	ctx.write_config_header('config.h')

def dist(ctx):
	ctx.excl	= ' **/.waf-1* **/*.pyc **/*.swp **/.git/'

def build(ctx):
	ctx.recurse('src')

def all(ctx):
	import Options
	Options.commands = ['configure', 'build'] + Options.commands
