# HashiCorp `vagrant` demo of **`vault`** HA Cluster using native Raft storage.
This repo contains a `Vagrantfile` mock of a [Vault](https://www.vaultproject.io/) (HA) High Availability cluster / setup using the Beta feature of [RAFT](https://raft.github.io/) [Storage (as detailed on the learn guide)](https://learn.hashicorp.com/vault/operations/raft-storage) with four (4) or more nodes nodes: vault2, vault3. etc as well as [auto-unsealing using Transit Secrets Engine](https://learn.hashicorp.com/vault/operations/autounseal-transit) (node: vault1). The RAFT Storage in Vault is Beta and available since [version 1.3 or later](https://releases.hashicorp.com/vault/).

[![demo](https://asciinema.org/a/304787.svg)](https://asciinema.org/a/304787?autoplay=1)


## Makeup & Concept
The first Vault node (vault1) is not part of cluster and is used merely for the auto-unsealing of the other cluster nodes. 
A depiction below shows relations & the network [connectivity and overall PRC, Gossip, UDP/TCP port](https://learn.hashicorp.com/vault/operations/ops-reference-architecture#network-connectivity-details) expected to be produced. When ready the lead (vault2) node can be destructively stopped to observe change in leader and continued HA on nodes vault3, vault4, etc.

```
  (RAFT Storage & HA)
    VAULT SERVERS:   ._________________.252         (Auto-unseal Transit)
                     |     vault2      |             .…………………………………………….200
                     | & lead at start |             ┊     vault1      ┊
                     |_________________|             ┊  transit unseal ┊
                     ▲                 ▲             └……………………………………………┘
                    /                   \
                   /                     \
    ._____________▼___.251            .___▼_____________.250
    |     vault3 &    |               |     vault4 &    |
    |     standby     |◄-------------►|     standby     |   ... + other
    |_________________|               |_________________|    nodes ...

```

**NOTE**: connectivity to vault1 is not drawn above (for simplicity).
Private IP Address Class D is defined in the **`Vagrantfile`** and can be adjusted to your local network if needed.
A.B.C.200 node is consider as the transit unseal node and the first raft cluster node is A.B.C.252 decrement with each higher vault node.


### Prerequisites
Ensure that you already have the following hardware & software requirements:
 
##### HARDWARE
 - **RAM** **4**+ Gb Free at least (ensure you're not hitting SWAP either or are < 100Mb)
 - **CPU** **4**+ Cores Free at least (2 or more per instance better) 
 - **Network** interface allowing IP assignment and interconnection in VirtualBox bridged mode for all instances.
 - - adjust `sNET='en0: Wi-Fi (Wireless)'` in **`Vagrantfile`** to match your system.

##### SOFTWARE
 - [**Virtualbox**](https://www.virtualbox.org/)
 - [**Virtualbox Guest Additions (VBox GA)**](https://download.virtualbox.org/virtualbox/)
 - > **MacOS** (aka OSX) - VirtualBox 6.x+ is expected to be shipped with the related .iso present under (eg):
 `/Applications/VirtualBox.app/Contents/MacOS/VBoxGuestAdditions.iso`
You may however need to download the .iso specific to your version (mount it) and execute the VBoxDarwinAdditions.pkg
 - [**Vagrant**](https://www.vagrantup.com/)
 - **Few** (**2-4**) **`shell`** or **`screen`** sessions to allow for multiple SSH sessions.
 - :lock: **NOTE**: An [enterprise license](https://www.hashicorp.com/products/vault/pricing/) will be required for [performance standbys](https://www.vaultproject.io/docs/enterprise/performance-standby/) & some other [replication](https://www.vaultproject.io/docs/enterprise/replication/) features (not needed for this demo but bare in mind if making related changes).


## Usage & Workflow
Refer to the contents of **`Vagrantfile`** for the number of instances, resources, Network, IP and provisioning steps. Other example changes like: **`Debian`** (or **`Ubuntu`**) may be set as the **OS** which have been confirmed to work the same (tested with: `Ubuntu: 18.04 - bionic` & `Debian: 10.3 - buster`).

The provided **`.sh`** script are installer helpers that download the latest binaries (or specific versions) and write configuration of RAFT servers, and the trainsit vault node - based on the numeric ending of **hostname**(s) (`*1` == vault transit, `*2` == vault cluster node1, `*3` == vault cluster node2, etc).

**Inline Environment Variables** can be set for specific versions and other settings that are part of `2.install_vault_raft.sh`.

```bash
vagrant up --provider virtualbox ;
# // ... output of provisioning steps.

vagrant global-status ; # should show running nodes
# id       name    provider   state   directory
# -------------------------------------------------------------------------------
# c4917e9  vault1  virtualbox running /home/auser/hashicorp.vagrant_vault-raft
# 9bdb8ec  vault2  virtualbox running /home/auser/hashicorp.vagrant_vault-raft
# c2c6a95  vault3  virtualbox running /home/auser/hashicorp.vagrant_vault-raft
# e62cece  vault4  virtualbox running /home/auser/hashicorp.vagrant_vault-raft

# // On a separate Terminal session check status of vault2 & cluster.
vagrant ssh vault2 ;
# // ...
vagrant@vault2:~$ \
vault status ;
# ...
# Cluster Name             vault-cluster-9b7ee41c
# Cluster ID               fd81f5ce-46f4-99c8-2ff4-274b3d24395f
# HA Enabled               true
# HA Cluster               https://192.168.10.252:8201
# HA Mode                  active

vagrant@vault2:~$ \
vault operator raft configuration -format=json | jq -r .data.config.servers[].address ;
# 192.168.10.252:8201
# 192.168.10.251:8201
# 192.168.10.250:8201

# // On a separate Terminal session check status of vault3 & its readiness for switch over.
vagrant ssh vault3 ;
# // ...
vagrant@vault3:~$ \
vault status ;
# Cluster Name             vault-cluster-9b7ee41c
# Cluster ID               fd81f5ce-46f4-99c8-2ff4-274b3d24395f
# HA Enabled               true
# HA Cluster               https://192.168.10.252:8201
# HA Mode                  standby
# Active Node Address      http://192.168.10.252:8200

# // Back on vault2
vagrant@vault2:~$ \
sudo service vault stop ;

# // Back on vault3
vagrant@vault3:~$ \
vault status ;
# Cluster Name             vault-cluster-9b7ee41c
# Cluster ID               fd81f5ce-46f4-99c8-2ff4-274b3d24395f
# HA Enabled               true
# HA Cluster               https://192.168.10.251:8201
# HA Mode                  active
vagrant@vault3:~$ \
vault kv get kv/apikey && vault kv patch kv/apikey webapp=3141 ;
# ====== Metadata ======
# // ...
# version          2

# // On a separate Terminal session observer vault4 as above.
# vagrant ssh vault4 ; # // ...
# // ... continue with other ops like restore, recovery, bringing vault1 back, etc.

# // ---------------------------------------------------------------------------
# when completely done:
vagrant destroy -f vault1 vault2 vault3 vault4 ; # ... destroy al
vagrant box remove -f debian/buster64 --provider virtualbox ; # ... delete box images
```


## Snapshots, Restoration & Removing a Cluster Member
Some of the related `vault operator` context not covered in detail include:

```
vault operator raft snapshot save FILE.snapshot ; # // taking a snapshots
vault operator raft snapshot restore FILE.snapshot ; # // restoring a snapshots
vault operator raft remove-peer NODE-ID/NODE-NAME ; # // removing a peer member
vault operator raft join IP/FQDN ; # // join raft via active node
```  


## Notes
This is intended as a mere practise / training exercise.

See also:
 - [hashicorp/vault-guides/operations/raft-storage](https://github.com/hashicorp/vault-guides/tree/main/operations/raft-storage)
 - [Vault Consul Storage Example](https://github.com/aphorise/hashicorp.vagrant_vault_consul)

Reference Material:
 - [Vault HA Cluster with Integrated Storage](https://learn.hashicorp.com/tutorials/vault/raft-storage?in=vault/raft)
------
