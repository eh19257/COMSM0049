# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "box" do |box|
                box.vm.box = "ubuntu/bionic64"
                box.vm.hostname = "SS-CW"
                box.vm.provider "virtualbox" do |virtualbox|
        virtualbox.name="SS-CW"
    end
 end
end
