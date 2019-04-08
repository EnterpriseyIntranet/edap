import os
import setuptools

SETUPDIR = os.path.dirname(__file__)
PKGDIR = os.path.join(SETUPDIR, 'src')

with open(os.path.join(SETUPDIR, 'README.md'), 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='edap',
    version='0.0.1',
    author='EnterpriseyIntranet',
    description="Python wrapper for LDAP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/EnterpriseyIntranet/edap",
    packages=setuptools.find_packages(PKGDIR),
    include_package_data=True,
    install_requires=['python-ldap'],
    package_dir={'': 'src'},
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        "Operating System :: OS Independent",
    ],
)
