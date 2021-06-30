IMAGE_NAME = "ubuntu/focal64"
N = 2

Vagrant.configure("2") do |config|

    config.vm.define "bmv2-1" do |switch|
        switch.vm.box = "leandrocdealmeida/bmv2-p4"
        switch.vm.hostname = "bmv2-1"
        #management network (IP - 192.168.56.200)
        switch.vm.network "private_network", ip: "192.168.56.200",name: "vboxnet0"
		switch.vm.network "private_network", ip: "fc10::1", mac: "080027bbbbbb",name: "vboxnet0"
        switch.vm.network "public_network", ip: "fc00::1", mac: "00154d000000",bridge: "vf0_0"
        switch.vm.provider "virtualbox" do |virtualbox|
			virtualbox.memory = "4096"
			virtualbox.cpus = "4"
        end
        switch.vm.provision "file", source: "code/ran.p4", destination: "ran.p4"
        switch.vm.provision "file", source: "code/commands2.txt", destination: "commands2.txt"
        switch.vm.provision "file", source: "code/gpt2.py", destination: "gpt2.py"
        switch.vm.provision "file", source: "code/flow.py", destination: "flow.py"
        #switch.vm.provision "ansible" do |ansible| 
        #    ansible.playbook = "switch-setup/switch-playbook-1.yml"
        #end
    end

    config.vm.define "bmv2-2" do |switch|
        switch.vm.box = "leandrocdealmeida/bmv2-p4"
        switch.vm.hostname = "bmv2-2"
        
        #management network (IP - 192.168.56.200)
        switch.vm.network "private_network", ip: "192.168.56.201",name: "vboxnet0"
        switch.vm.network "private_network", ip: "fc20::1", mac: "080027cccccc", name: "vboxnet1"
        switch.vm.network "public_network", ip: "fc00::5", mac: "00154d000004",bridge: "vf0_4"
        switch.vm.provider "virtualbox" do |virtualbox|
			virtualbox.memory = "4096"
			virtualbox.cpus = "4"
        end
        switch.vm.provision "file", source: "code/ran.p4", destination: "ran.p4"
        switch.vm.provision "file", source: "code/commands2.txt", destination: "commands2.txt"
        #switch.vm.provision "ansible" do |ansible| 
        #    ansible.playbook = "switch-setup/switch-playbook-2.yml"
        #end
    end

end
