#!/usr/bin/env python3

import os
import sys


def main():
    # Check if the handler argument is provided
    if 2 == len(sys.argv):
        os.environ['_HANDLER'] = sys.argv[1]

    # If no argument is provided, fall back to the existing environment variable
    elif 1 == len(sys.argv):
        if not os.environ.get('_HANDLER'):
            print('a handler name is required to be the first argument or set via the _HANDLER environment variable', file=sys.stderr)
            sys.exit(142)

    # Fail immediately if too many arguments are passed
    else:
        print('exactly zero or one arguments are required', file=sys.stderr)
        sys.exit(142)

    runtime_entrypoint = '/var/runtime/bootstrap'

    # 4. Emulate the RIE execution logic
    if not os.environ.get('AWS_LAMBDA_RUNTIME_API'):
        # Local execution fallback
        rie_binary = '/usr/local/bin/aws-lambda-rie'
        os.execv(rie_binary, [rie_binary, runtime_entrypoint])
    else:
        # Production AWS Lambda cloud execution
        os.execv(runtime_entrypoint, [runtime_entrypoint])

if '__main__' == __name__:
    main()
