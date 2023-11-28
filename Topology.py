from mininet.topo import Topo

class Topology(Topo):
    
    def __init__(self, switches=1):
        Topo.__init__(self)

        switches = self.validSwitches(switches)
        print("Cantidad de switches: %s" % (switches))
     
        print("Agregamos los hosts h1, h2, h3 y h4")
        hostIzquierda1 = self.addHost('h1')
        hostIzquierda2 = self.addHost('h2')
        hostDerecha3 = self.addHost('h3')
        hostDerecha4 = self.addHost('h4')

        print("Agregamos el switch: s1")
        primerSwitch = self.addSwitch('s1')
        ultimoSwitch = primerSwitch

        for nroSwitch in range(2, switches + 1):
            nombreSwitch = 's%i' % (nroSwitch)
            print("Agregamos el switch: %s" % (nombreSwitch))
            switchActual = self.addSwitch(nombreSwitch)

            print("Agreamos un link entre los swtiches: %s y %s" % (ultimoSwitch, switchActual))
            self.addLink(ultimoSwitch, switchActual)
            
            ultimoSwitch = switchActual

        print("Agregamos un link entre el host: %s y el switch %s (primer switch)" % (hostIzquierda1, primerSwitch))
        self.addLink(hostIzquierda1, primerSwitch)

        print("Agregamos un link entre el host: %s y el switch %s (primer switch)" % (hostIzquierda2, primerSwitch))
        self.addLink(hostIzquierda2, primerSwitch)

        print("Agregamos un link entre el host: %s y el switch %s (ultimo switch)" % (hostDerecha3, ultimoSwitch))
        self.addLink(hostDerecha3, ultimoSwitch)

        print("Agregamos un link entre el host: %s y el switch %s (ultimo switch)" % (hostDerecha4, ultimoSwitch))
        self.addLink(hostDerecha4, ultimoSwitch)


    def validSwitches(self, switches):
        isSwitchesOK = False
        validSwitches = None

        while not isSwitchesOK:
            try:
                validSwitches = int(switches)
                if validSwitches < 1:
                    raise Exception
                isSwitchesOK = True
            except:
                print("Ocurrió un error con la cantidad de switches. La cantidad de switched debe ser un entero mayor o igual que 1")
                switches = input("Indique la cantidad de switches: ") 
              
        return validSwitches

topos = {'topology': (lambda switches:  Topology(switches))}