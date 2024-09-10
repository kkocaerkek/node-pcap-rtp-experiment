const fs = require('fs');
const PcapParser = require('pcap-parser');
const rtpParser = require('rtp-parser');
const { PassThrough } = require('stream');
const { EventEmitter } = require('events');


/*
    Parses pcap file containing two channel RTP (8000 Hz alaw) packets. Extracts RTP packets from pcap and combine two channels into a stereo raw audio file 
*/ 

const pcapPath = 'sip_call_rtp_packets.pcap'; // input file path
const outputPathStereo = 'stereo.raw'; // raw audio output path

class RTPPacketReader extends EventEmitter {
    constructor() {
        super();
        this.streams = new Map();
    }

    push(UDPPacket) {
        this.socket.write(UDPPacket);
    }

    bind() {
        this.socket = new PassThrough();

        this.socket.on('data', (data) => {
            const udpHeader = data.slice(34, 42);
            const srcPort = udpHeader.readUInt16BE(0);
            const udpLength = udpHeader.readUInt16BE(4);
            const udpPayload = data.slice(42, 42 + udpLength - 8);

            try{
                const rtpPacket = rtpParser.parseRtpPacket(udpPayload);
                this.emit(`data-${srcPort}`, rtpPacket.payload);
            }catch (e) {
                //skip non rtp packets
                //console.log(`not an rtp packet: ${e.message}`);
            }
        });
    }

    createStream(port) {
        const stream = new PassThrough();
        stream.on('close', () => {
            this.removeAllListeners(`data-${port}`);
        });

        this.once(`data-${port}`, () => {
           console.log(`Audio Stream started from port ${port}`);
        });

        this.on(`data-${port}`, (data) => {
            if (!stream.writeable) {
                stream.write(data);
            } else {
                console.log('Trying to write Audio to Passthrough stream when stream is not in a writeable state');
            }
        });

        this.streams.set(port, stream);

        return stream;
    }

    endStream(port) {
        this.removeAllListeners(`data-${port}`);
        let stream = this.streams.get(port);
        if (stream) {
            stream.end();
            this.streams.delete(port);
            console.log(`read stream deleted on port: ${port}`);
        }
    }
}

const rtpReader = new RTPPacketReader();
rtpReader.bind();

const leftPort = 8000;
const rightPort = 40376;

const readStreamLeft = rtpReader.createStream(leftPort);
const readStreamRight = rtpReader.createStream(rightPort);


const writableStreamStereo = fs.createWriteStream(outputPathStereo);

let leftBuffer = Buffer.alloc(0);
let rightBuffer = Buffer.alloc(0);

readStreamLeft.on("data", (data) => {
    leftBuffer = Buffer.concat([leftBuffer, data]);
    processAudioBuffers();
});

readStreamRight.on('data', (data) => {
    rightBuffer = Buffer.concat([rightBuffer, data]);
    processAudioBuffers();
});

function processAudioBuffers() {
    const minLength = Math.min(leftBuffer.length, rightBuffer.length);

    if (minLength > 0) {
        // fetch data as minimum length from buffers
        const leftData = leftBuffer.slice(0, minLength);
        const rightData = rightBuffer.slice(0, minLength);

        // combine two mono buffers into a stereo buffer
        const stereoBuffer = Buffer.alloc(minLength * 2);
        for (let i = 0; i < minLength; i++) {
            stereoBuffer[i * 2] = leftData[i];   // sol kanal
            stereoBuffer[i * 2 + 1] = rightData[i]; // sağ kanal
        }

        writableStreamStereo.write(stereoBuffer);

        // remove preccessed parts from mono buffers
        leftBuffer = leftBuffer.slice(minLength);
        rightBuffer = rightBuffer.slice(minLength);
    }
}


const parser = PcapParser.parse(fs.createReadStream(pcapPath));

parser.on('packet', (packet) => {
    const ethertype = packet.data.readUInt16BE(12);

    // process only IPv4 packets
    if (ethertype === 0x0800) {
        const ipHeader = packet.data.slice(14, 34); 
        const protocol = ipHeader.readUInt8(9); 

        // process only UDP packets
        if (protocol === 17) {
            const udpHeader = packet.data.slice(34, 42);
            const udpPayload = packet.data.slice(42);

            rtpReader.push(packet.data);
        }
    }
});

parser.on('end', () => {
    console.log('PCAP parsing completed.');
    writableStreamStereo.end();
    rtpReader.endStream(leftPort);
    rtpReader.endStream(rightPort);
});
