from distutils.core import setup

setup(
    name='Rets',
    version='0.1',
    description='Python RETS Client',
    long_description=open('README.md').read(),
    author='Autoprop',
    author_email='wimbersky@autoprop.ca',
    url='https://github.com/wetcoastdev/rets',
    packages=['requests', 'xml'],
    license='MIT',
)
