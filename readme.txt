You are required to install the Nuclei backend engine
using the command on below

1. sudo apt install golang -y

2. GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

3. echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

4. Store the nuclei-custom folder in the same directory as nuclei-templates located

5. python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

6. flask run --host=0.0.0.0 --port=5000

* The reset password require your own Gmail setup to function correctly