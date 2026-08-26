// Azure Bicep template for the munnel tunnel server.
// Provisions: VNet + subnet, NSG (22/80/443/7001), static public IP, NIC,
// Ubuntu 22.04 VM with cloud-init userData (Docker + /opt/munnel/.env + unit).
//
// Deploy via deploy/azure/deploy.sh, or directly:
//   az group create -n rg-munnel-westeurope -l westeurope
//   az deployment group create -g rg-munnel-westeurope -f deploy/azure/main.bicep \
//     --parameters name=munnel adminKey="$(cat ~/.ssh/munnel_deploy_key.pub)" \
//     userData="$(base64 < userdata.yaml | tr -d '\n')"

param location string = resourceGroup().location
param name string = 'munnel'
param vmSize string = 'Standard_D2als_v7'   // 2 vCPU / 4 GiB — ~€70/mo
param adminUsername string = 'azureuser'
@description('SSH public key (ed25519) for the admin user')
param adminKey string
@description('base64-encoded cloud-init user-data (see deploy/cloud-init.yaml)')
param userData string

resource vnet 'Microsoft.Network/virtualNetworks@2024-03-01' = {
  name: '${name}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-03-01' = {
  parent: vnet
  name: 'default'
  properties: { addressPrefix: '10.0.0.0/24' }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-03-01' = {
  name: '${name}-nsg'
  location: location
  properties: {
    securityRules: [
      { name: 'AllowSSH';    properties: { priority: 100; protocol: 'Tcp'; access: 'Allow'; direction: 'Inbound'; sourceAddressPrefix: '*'; sourcePortRange: '*'; destinationAddressPrefix: '*'; destinationPortRange: '22' } }
      { name: 'AllowHTTP';   properties: { priority: 110; protocol: 'Tcp'; access: 'Allow'; direction: 'Inbound'; sourceAddressPrefix: '*'; sourcePortRange: '*'; destinationAddressPrefix: '*'; destinationPortRange: '80' } }
      { name: 'AllowHTTPS';  properties: { priority: 120; protocol: 'Tcp'; access: 'Allow'; direction: 'Inbound'; sourceAddressPrefix: '*'; sourcePortRange: '*'; destinationAddressPrefix: '*'; destinationPortRange: '443' } }
      { name: 'AllowMunnel'; properties: { priority: 130; protocol: 'Tcp'; access: 'Allow'; direction: 'Inbound'; sourceAddressPrefix: '*'; sourcePortRange: '*'; destinationAddressPrefix: '*'; destinationPortRange: '7001' } }
    ]
  }
}

resource pip 'Microsoft.Network/publicIPAddresses@2024-03-01' = {
  name: '${name}-pip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-03-01' = {
  name: '${name}-nic'
  location: location
  properties: {
    networkSecurityGroup: { id: nsg.id }
    ipConfigurations: [
      {
        name: 'ipconfig'
        properties: {
          subnet: { id: subnet.id }
          publicIPAddress: { id: pip.id }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: '${name}-vm'
  location: location
  properties: {
    hardwareProfile: { vmSize: vmSize }
    osProfile: {
      computerName: take(name, 15)
      adminUsername: adminUsername
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [{
            path: '/home/${adminUsername}/.ssh/authorized_keys'
            keyData: adminKey
          }]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        name: '${name}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id; properties: { primary: true } }]
    }
    userData: userData
  }
}

output publicIp string = pip.properties.ipAddress
output vmName string = vm.name
output sshTarget string = '${adminUsername}@${pip.properties.ipAddress}'