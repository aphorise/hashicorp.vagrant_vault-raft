# -*- mode: ruby -*-
# vi: set ft=ruby :
iN=4  # // number of vault instance >= 4
sVUSER='vagrant'  # // vagrant user
sHOME="/home/#{sVUSER}"  # // home path for vagrant user
sNET='en0: Wi-Fi (Wireless)'  # // network adaptor to use for bridged mdoe
sIP_CLASS_D='192.168.10'  # // NETWORK CIDR for Consul configs.
sIP="#{sIP_CLASS_D}.200"

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/bionic64"  # // OS
#  config.vm.box = "debian/buster64"  # // OS
#  config.vm.box_version = "10.3.0"  # // OS Version

  config.vm.provider "virtualbox" do |v|
    v.memory = 1024  # // RAM / Memory
    v.cpus = 1  # // CPU Cores / Threads
  end

  # // allow for SSHD on all interfaces & setup default identity files for ssh
  config.vm.provision "shell", inline: 'sed -i "s/#ListenAddress/ListenAddress/g" /etc/ssh/sshd_config'
  config.vm.provision "shell", inline: 'sed -i "s/#.*IdentityFile ~\/\.ssh\/id_rsa/    IdentityFile ~\/\.ssh\/id_rsa/g" /etc/ssh/ssh_config'
  config.vm.provision "shell", inline: 'sed -i "s/.*IdentityFile ~\/\.ssh\/id_rsa/    IdentityFile ~\/\.ssh\/id_rsa\n    IdentityFile ~\/\.ssh\/id_rsa2/g" /etc/ssh/ssh_config'
  config.vm.provision "shell", path: "1.install_commons.sh"
  config.vm.provision "file", source: "2.install_vault_raft.sh", destination: "#{sHOME}/install_vault.sh"

  # // VAULT Server Nodes as Consule Clients as well.
  (1..iN).each do |iX|
    config.vm.define vm_name="vault#{iX}" do |vault_node|
      vault_node.vm.hostname = vm_name
      if iX == 1 then
        vault_node.vm.network "public_network", bridge: "#{sNET}", ip: "#{sIP}"
        vault_node.vm.provision "shell", inline: "/bin/bash -c '#{sHOME}/install_vault.sh'"
      end
      if iX == 2 then 
        vault_node.vm.network "public_network", bridge: "#{sNET}", ip: "#{sIP_CLASS_D}.#{254-iX}"
        vault_node.vm.provision "file", source: ".vagrant/machines/vault1/virtualbox/private_key", destination: "#{sHOME}/.ssh/id_rsa"
        vault_node.vm.provision "shell", inline: "/bin/bash -c 'IP_TRANSIT=#{sIP} #{sHOME}/install_vault.sh'"
      end
      if iX > 2 then 
        vault_node.vm.network "public_network", bridge: "#{sNET}", ip: "#{sIP_CLASS_D}.#{254-iX}"
        vault_node.vm.provision "file", source: ".vagrant/machines/vault1/virtualbox/private_key", destination: "#{sHOME}/.ssh/id_rsa"
        vault_node.vm.provision "file", source: ".vagrant/machines/vault2/virtualbox/private_key", destination: "#{sHOME}/.ssh/id_rsa2"
        vault_node.vm.provision "shell", inline: "/bin/bash -c 'IP_VAULT_ACTIVE=#{sIP_CLASS_D}.#{254-2} IP_TRANSIT=#{sIP} #{sHOME}/install_vault.sh'"
      end
    end
  end

end
