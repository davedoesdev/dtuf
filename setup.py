import os
from setuptools import setup

def read(name):
    return open(os.path.join(os.path.dirname(__file__), name)).read()

setup(
    name='python-dtuf',
    version='1.1.0',
    description="Docker registry bindings for The Update Framework",
    long_description=read('README.rst'),
    keywords='docker registry tuf update framework',
    author='David Halls',
    author_email='dave@davedoesdev.com',
    url='https://github.com/davedoesdev/dtuf',
    license='MIT',
    packages=['dtuf'],
    entry_points={'console_scripts': ['dtuf=dtuf.main:main']},
    install_requires=['tuf>=0.10.0',
                      'python-dxf>=4.0.1',
                      'fasteners>=0.14.1',
                      'tqdm>=4.10.0',
                      'cryptography>=1.5',
                      'pytimeparse>=1.1.5',
                      'decorator>=4.0.10',
                      'iso8601>=0.1.11',
                      'pycrypto>=2.6.1']
)
