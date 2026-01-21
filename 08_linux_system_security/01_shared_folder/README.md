# Step 1: Create a new user and group

sudo useradd -m -s /usr/bin/sh alice
sudo passwd alice
sudo groupadd devs
sudo usermod -aG devs alice
sudo usermod -aG devs jedha

# Step 2: Create a Shared Folder

sudo mkdir /shared_folder
sudo chown root:devs /shared_folder
sudo chmod 770 /shared_folder

# Step 4: Change Default Behaviour

sudo chmod g+s /shared_folder


# Step 5: Password Policy
vim /etc/pam.d/common-password

jedha@ubuntu:~$ grep -v '^#' /etc/pam.d/common-password | grep -v '^$'
minlen = 12 
dcredit = -1 
ucredit = -1 
ocredit = -1
