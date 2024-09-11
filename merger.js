const fs = require('fs');
const PcapParser = require('pcap-parser');
const rtpParser = require('rtp-parser');
const { PassThrough } = require('stream');
const { EventEmitter } = require('events');


/*
    Parses pcap file containing two channel RTP (8000 Hz ulaw) packets. 
    Extracts RTP packets from pcap and combine two channels into a stereo raw audio file 
*/ 

// ********* YOU CAN TRY JITTER AND PACKET LOSS EFFECTS BY CHANGING THESE VALUES BELOW ******** 
const jitterBufferMS = 100; // miliseconds
const packetLossSimulationProbability = 0.2; // 0-1
const jitterSimulationProbability = 0.0; // 0 - 1
// ***********************************************************************************



const pcapPath = 'gh-g711-test-rtp.pcap'; // input file path
const outputPathStereo = 'stereo.raw'; // raw audio output path

const leftPort = 14286; // channel 1 src port in pcap file
const rightPort = 14678; // channel 2 src port in pcap file

//*********** 
const packetFrequencyMS = 20; // send packet every 20 milliseconds
const jitterBufferSize = Math.floor(jitterBufferMS / packetFrequencyMS);
const weightedCoinFlip = (weight) => Math.random() <= weight; // returns random boolean based on probability weight


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
            const udpHeader = data.slice(36, 44);
            const srcPort = udpHeader.readUInt16BE(0);
            const udpLength = udpHeader.readUInt16BE(4);
            const udpPayload = data.slice(44, 44 + udpLength - 8);
            //console.log(`srcPort: ${srcPort}`);
            try{
                //const rtpPacket = rtpParser.parseRtpPacket(udpPayload);

                
                this.emit(`data-${srcPort}`, udpPayload);
            }catch (e) {
                //skip non rtp packets
                console.log(`not an rtp packet: ${e.message}`);
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

const readStreamLeft = rtpReader.createStream(leftPort);
const readStreamRight = rtpReader.createStream(rightPort);


const writableStreamStereo = fs.createWriteStream(outputPathStereo);

let leftBuffer = []
let rightBuffer = []

readStreamLeft.on("data", (data) => {
    const rtpPacket = rtpParser.parseRtpPacket(data);
    leftBuffer.push(rtpPacket);
    leftBuffer.sort((a, b) => {a.sequenceNumber - b.sequenceNumber});
    //console.log(`left buffer len: ${leftBuffer.length} jitter buffer size: ${jitterBufferSize}`);
    if(leftBuffer.length > jitterBufferSize){
        processAudioBuffers();
    }
});

readStreamRight.on('data', (data) => {
    const rtpPacket = rtpParser.parseRtpPacket(data);
    rightBuffer.push(rtpPacket);
    rightBuffer.sort((a, b) =>  a.sequenceNumber - b.sequenceNumber );
    //console.log(`right buffer len: ${rightBuffer.length} jitter buffer size: ${jitterBufferSize}`);
    if(rightBuffer.length > jitterBufferSize){
        processAudioBuffers();
    }
});


function getRTPPayload(data) {
    const udpHeader = data.slice(36, 44);
    const udpLength = udpHeader.readUInt16BE(4);
    const udpPayload = data.slice(44, 44 + udpLength - 8);
    const rtpPacket = rtpParser.parseRtpPacket(udpPayload);

    return rtpPacket.payload;
}

function processAudioBuffers() {
    const minLength = Math.min(leftBuffer.length, rightBuffer.length);
    //console.log(leftBuffer.map(obj => obj.sequenceNumber).join(', '));
    //console.log(rightBuffer.map(obj => obj.sequenceNumber).join(', '));
    for(let i = 0; i < minLength; i++){
        // fetch data as minimum length from buffers
        const leftItem = leftBuffer.shift();
        const leftData = leftItem.payload;
        const rightItem = rightBuffer.shift();
        const rightData = rightItem.payload;
        // combine two mono buffers into a stereo buffer
        const stereoBufferLen = Math.min(leftData.length, rightData.length);
        //console.log(`Stereo buffer length: ${stereoBufferLen}`);
        const stereoBuffer = Buffer.alloc(stereoBufferLen * 2);
        for (let i = 0; i < stereoBufferLen; i++) {
            stereoBuffer[i * 2] = leftData[i];   // sol kanal
            stereoBuffer[i * 2 + 1] = rightData[i]; // sağ kanal
        }
        //console.log('stereo buffer:');
        //console.log(stereoBuffer);
        writableStreamStereo.write(stereoBuffer);
    }
}


const parser = PcapParser.parse(fs.createReadStream(pcapPath));

parser.on('packet', (packet) => {
    const ethertype = packet.data.readUInt16BE(14);
    // process only IPv4 packets
    if (ethertype === 0x0800) {
        const ipHeader = packet.data.slice(16, 36);
        const protocol = ipHeader.readUInt8(9); 
        
        
        // process only UDP packets
        if (protocol === 17) {
            const udpHeader = packet.data.slice(36, 44);
            const udpPayload = packet.data.slice(44);
            
            let latency = packetFrequencyMS;
            // simulate jitter if enabled
            if(jitterSimulationProbability > 0 && weightedCoinFlip(jitterSimulationProbability)){
                latency = latency + (Math.random() * (packetFrequencyMS / 2));
                console.log(`simulating jitter. latency: ${latency}`);
            }

            let dropPacket = false;
            //simulate packet loss if enabled
            if(packetLossSimulationProbability > 0 && weightedCoinFlip(packetLossSimulationProbability)){
                dropPacket = true;
                console.log(`simulating packet loss`);
            }

            if(!dropPacket){
                
                // don't send immediately, simulate streaming 
                setTimeout(
                    function() { rtpReader.push(packet.data);  }
                , latency);
                
            }
            
        }
    }
});


parser.on('end', () => {
    console.log('PCAP parsing completed.');
    setTimeout(() => {
        rtpReader.endStream(leftPort);
        rtpReader.endStream(rightPort);
        writableStreamStereo.end();
    }, 3000);
});

