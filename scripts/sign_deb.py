#!/usr/bin/env python
import subprocess
import tempfile
import argparse
import os.path
import shutil
import os

parser = argparse.ArgumentParser()
parser.add_argument('--deb', type=str, required=True)

if __name__ == '__main__':
    args = parser.parse_args()
    deb_path = os.path.abspath(args.deb)
    deb = os.path.basename(args.deb)

    with tempfile.TemporaryDirectory() as working_dir:
        os.chdir(working_dir)

        subprocess.check_output(('ar', 'x', deb_path))
        subprocess.check_output(' | '.join((
            'cat debian-binary control.tar.gz data.tar.gz',
            'gpg -abs -o _gpgorigin')), shell=True)
        subprocess.check_output([
            'ar', 'rc', deb, 'debian-binary', 'control.tar.gz',
            'data.tar.gz', '_gpgorigin'
        ])
        shutil.move(deb, deb_path)
