import os
from setuptools import setup

def read(name):
    return open(os.path.join(os.path.dirname(__file__), name)).read()

setup(
    name='python_dtuf',
    version='0.0.1',
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
                      'python_dxf>=2.0.0',
                      'fasteners>=0.14.1',
                      'tqdm>=3.1.4',
                      'cryptography>=1.1.2',
                      'pytimeparse>=1.1.5',
                      'decorator>=4.0.6',
                      'iso8601>=0.1.11',
                      'pycrypto>=2.6.1']
)
