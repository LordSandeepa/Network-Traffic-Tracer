from flask import Flask, request, render_template, send_file
import dpkt
import socket
import pygeoip
from io import BytesIO

gi = pygeoip.GeoIP('GeoLiteCity.dat')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'pcap_file' not in request.files or 'src_ip' not in request.form:
        return "No file or source IP provided", 400
    
    src_ip = request.form['src_ip']
    file = request.files['pcap_file']
    
    if file.filename == '':
        return "No selected file", 400

    pcap_data = file.read()
    pcap_file = BytesIO(pcap_data)
    pcap = dpkt.pcap.Reader(pcap_file)

    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">' \
                '<LineStyle>' \
                '<width>1.5</width>' \
                '<color>501400E6</color>' \
                '</LineStyle>' \
                '</Style>'
    kmlfooter = '</Document>\n</kml>\n'
    kmldoc = kmlheader + plotIPs(pcap, src_ip) + kmlfooter

    output_file = 'output.kml'
    with open(output_file, 'w') as f:
        f.write(kmldoc)

    return send_file(output_file, as_attachment=True)

def plotIPs(pcap, src_ip):
    kmlPts = ''
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if isinstance(ip, dpkt.ip.IP):  # IPv4
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
            elif isinstance(ip, dpkt.ip6.IP6):  # IPv6
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                continue
            KML = retKML(dst, src_ip)
            kmlPts += KML
        except Exception as e:
            print(f"Error processing packet: {e}")  # Debug print
            continue
    return kmlPts

def retKML(dstip, srcip):
    try:
        dst = gi.record_by_name(dstip)
        src = gi.record_by_name(srcip)
        if not dst or not src:
            return ''
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        ) % (dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except:
        return ''

if __name__ == '__main__':
    app.run(debug=True)
