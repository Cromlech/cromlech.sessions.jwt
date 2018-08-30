# -*- coding: utf-8 -*-

from os.path import join
from setuptools import setup, find_packages

name = 'cromlech.sessions.jwt'
version = '0.0.1'
readme = open('README.txt').read()
history = open(join('docs', 'HISTORY.txt')).read()

install_requires = [
    'setuptools',
    'cromlech.jwt',
]

tests_require = [
    'WebTest',
]


setup(name=name,
      version=version,
      description=("HTTP Session using JWT and Cookies."),
      long_description=readme + '\n\n' + history,
      keywords='Cromlech Session',
      author='The Cromlech Team',
      author_email='dolmen@list.dolmen-project.org',
      url='http://gitweb.dolmen-project.org/',
      license='ZPL',
      package_dir={'': 'src'},
      packages=find_packages('src', exclude=['ez_setup']),
      namespace_packages=['cromlech', 'cromlech.sessions'],
      include_package_data=True,
      zip_safe=False,
      tests_require=tests_require,
      install_requires=install_requires,
      extras_require={'test': tests_require},
      test_suite="cromlech.sessions.jwt",
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Web Environment',
          'Intended Audience :: Other Audience',
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
      ],
)
