#!/usr/bin/python

from distutils.core import setup

setup(name='kbapi',
      version='1.0',
      description='Python modules for the KB API',
      author='Jonathan Reed',
      packages=['kb_api'],
      package_data={'kb_api': ['templates.admin/*',
                               'static/images/*',
                               'static/styles/*',
                           ]},
      scripts=['authdb.py', 'debug.py'],
      data_files=[('', ['kb_api.wsgi'])]
      )
