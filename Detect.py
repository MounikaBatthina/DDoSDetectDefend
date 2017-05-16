#!/usr/bin/python3
import pyshark,sqlite3
count = 0
syn = 0
syn_ack = 0
ack = 0
conn = sqlite3.connect('detect.db')

def packet_captured(packet):
	
	global count,syn,syn_ack,ack,conn
	count+=1
	if(int(packet.tcp.flags,16) is 2):		
		syn+=1	
	elif(int(packet.tcp.flags,16) is 16):
		ack+=1		
	elif(int(packet.tcp.flags,16) is 18):
		syn_ack+=1

	c=conn.cursor()
	data = [(packet.ip.src,syn-ack,count)]
	c.execute("INSERT OR REPLACE INTO detection VALUES(?, ?, ?)".format(data), (packet.ip.src, syn-ack,count))	
	conn.commit()
	t = (packet.ip.src,)
	c.execute('SELECT count_diff FROM detection WHERE ip=?', t)
	print(c.fetchone())
	print('IP : '+str(packet.ip.src)+' Count : '+str(count)+', Syn : '+str(syn)+', Ack : '+str(ack)+', Syn_Ack : '+str(syn_ack)+'')

def main():	
	capture = pyshark.LiveCapture(interface='ens33', capture_filter='tcp')
	capture.apply_on_packets(packet_captured)	

def truncate():
	c=conn.cursor()
	c.execute("delete from detection")
	conn.commit()


if __name__ == '__main__':	
	main()
	#truncate()
