# -*- coding: utf-8 -*-

import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

exec(open('skyhook/version.py').read())

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='skyhook',
    version=__version__,
    packages=['skyhook'],
    include_package_data=True,
    license='BSD License',  # example license
    description='Skyhook ELG client.',
    long_description=README,
    url='https://github.com/anfema/python-skyhook',
    author='Johannes Schriewer',
    author_email='j.schriewer@anfe.ma',
    install_requires=[
        "PyCrypto"
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License', # example license
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
    ],
)
