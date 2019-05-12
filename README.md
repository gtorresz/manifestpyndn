# manifestpyndn

To setup the experiment:

0. Install dependencies

        pip3 install -r requirements.txt

1. Setup NDN-ABS authority and attribute set for the experiment

        ndnabs setup /icn2019/test/authority

        ndnabs gen-secret attribute1 attribute2 | ndnabs install-secret

3. Generate appropriate sized file

        head -c 10M </dev/urandom > myfile

4. Run the experiment and record the result

        ./abs_experiment.py myfile
