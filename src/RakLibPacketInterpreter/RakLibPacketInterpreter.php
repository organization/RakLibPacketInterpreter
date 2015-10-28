<?php

namespace RakLibPacketInterpreter;

use pocketmine\plugin\PluginBase;
use pocketmine\event\Listener;
use pocketmine\command\CommandSender;
use pocketmine\command\Command;
use pocketmine\command\PluginCommand;
use raklib\protocol\ACK;
use raklib\protocol\ADVERTISE_SYSTEM;
use raklib\protocol\DATA_PACKET_0;
use raklib\protocol\DATA_PACKET_1;
use raklib\protocol\DATA_PACKET_2;
use raklib\protocol\DATA_PACKET_3;
use raklib\protocol\DATA_PACKET_4;
use raklib\protocol\DATA_PACKET_5;
use raklib\protocol\DATA_PACKET_6;
use raklib\protocol\DATA_PACKET_7;
use raklib\protocol\DATA_PACKET_8;
use raklib\protocol\DATA_PACKET_9;
use raklib\protocol\DATA_PACKET_A;
use raklib\protocol\DATA_PACKET_B;
use raklib\protocol\DATA_PACKET_C;
use raklib\protocol\DATA_PACKET_D;
use raklib\protocol\DATA_PACKET_E;
use raklib\protocol\DATA_PACKET_F;
use raklib\protocol\NACK;
use raklib\protocol\OPEN_CONNECTION_REPLY_1;
use raklib\protocol\OPEN_CONNECTION_REPLY_2;
use raklib\protocol\OPEN_CONNECTION_REQUEST_1;
use raklib\protocol\OPEN_CONNECTION_REQUEST_2;
use raklib\protocol\Packet;
use raklib\protocol\UNCONNECTED_PING;
use raklib\protocol\UNCONNECTED_PING_OPEN_CONNECTIONS;
use raklib\protocol\UNCONNECTED_PONG;
use raklib\protocol\DataPacket;
use raklib\RakLib;
use raklib\protocol\EncapsulatedPacket;
use raklib\protocol\SERVER_HANDSHAKE_DataPacket;

class RakLibPacketInterpreter extends PluginBase implements Listener {
	private $packetPool = [ ];
	const HANDSHAKE = 9;
	const STATISTICS = 0;
	const STATE_UNCONNECTED = 0;
	const STATE_CONNECTING_1 = 1;
	const STATE_CONNECTING_2 = 2;
	const STATE_CONNECTED = 3;
	public function onEnable() {
		@mkdir ( $this->getDataFolder () );
		$this->registerPackets ();
		$this->getServer ()->getPluginManager ()->registerEvents ( $this, $this );
		$this->registerCommand ( "raklib", "raklib.interpreter", "RankLib packet translation.", "/raklib <hex>" );
	}
	public function registerCommand($name, $permission, $description = "", $usage = "") {
		$commandMap = $this->getServer ()->getCommandMap ();
		$command = new PluginCommand ( $name, $this );
		$command->setDescription ( $description );
		$command->setPermission ( $permission );
		$command->setUsage ( $usage );
		$commandMap->register ( $name, $command );
	}
	public function onCommand(CommandSender $player, Command $command, $label, array $args) {
		if ($command->getName () != "raklib")
			return false;
		if (! isset ( $args [0] ))
			return false;
		$args [0] = hex2bin ( $args [0] );
		
		$pid = \ord ( $args [0] {0} );
		$this->getLogger ()->info ( "PID IS 0x" . dechex ( $pid ) );
		if (($packet = $this->getPacketFromPool ( $pid )) !== \null) {
			$this->getLogger ()->info ( "Interpretation succeeded." );
			$packet->buffer = $args [0];
			$this->handlePacketProcess ( $packet );
		} elseif ($args [0] !== "") {
			echo "streamRaw returned\n";
			$this->streamRaw ( $args [0] );
		} else {
			$this->getLogger ()->info ( "Interpretation failed." );
		}
		return true;
	}
	public function streamRaw($payload, $address = "127.0.0.1", $port = "19132") {
		$buffer = \chr ( RakLib::PACKET_RAW ) . \chr ( \strlen ( $address ) ) . $address . \pack ( "n", $port ) . $payload;
		$this->handlePacket ( $buffer );
	}
	/**
	 *
	 * @return bool
	 */
	public function handlePacket($packet) {
		$id = \ord ( $packet {0} );
		$offset = 1;
		if ($id === RakLib::PACKET_ENCAPSULATED) {
			$this->getLogger ()->info ( "PACKET_ENCAPSULATED PACKET" );
			$len = \ord ( $packet {$offset ++} );
			$identifier = \substr ( $packet, $offset, $len );
			$offset += $len;
			$flags = \ord ( $packet {$offset ++} );
			$buffer = \substr ( $packet, $offset );
			$this->handleEncapsulated ( $identifier, EncapsulatedPacket::fromBinary ( $buffer, \true ), $flags );
		} elseif ($id === RakLib::PACKET_RAW) {
			$this->getLogger ()->info ( "PACKET_RAW PACKET" );
			$len = \ord ( $packet {$offset ++} );
			$address = \substr ( $packet, $offset, $len );
			$offset += $len;
			$port = \unpack ( "n", \substr ( $packet, $offset, 2 ) ) [1];
			$offset += 2;
			$payload = \substr ( $packet, $offset );
			$this->handleRaw ( $address, $port, $payload );
		} elseif ($id === RakLib::PACKET_SET_OPTION) {
			$this->getLogger ()->info ( "PACKET_SET_OPTION PACKET" );
			$len = \ord ( $packet {$offset ++} );
			$name = \substr ( $packet, $offset, $len );
			$offset += $len;
			$value = \substr ( $packet, $offset );
			$this->handleOption ( $name, $value );
		} elseif ($id === RakLib::PACKET_OPEN_SESSION) {
			$this->getLogger ()->info ( "PACKET_OPEN_SESSION PACKET" );
			$len = \ord ( $packet {$offset ++} );
			$identifier = \substr ( $packet, $offset, $len );
			$offset += $len;
			$len = \ord ( $packet {$offset ++} );
			$address = \substr ( $packet, $offset, $len );
			$offset += $len;
			$port = \unpack ( "n", \substr ( $packet, $offset, 2 ) ) [1];
			$offset += 2;
			$clientID = Binary::readLong ( \substr ( $packet, $offset, 8 ) );
			// $this->instance->openSession ( $identifier, $address, $port, $clientID );
			$this->getLogger ()->info ( "IT IS OPEN SESSION PACKET" );
		} elseif ($id === RakLib::PACKET_CLOSE_SESSION) {
			$len = \ord ( $packet {$offset ++} );
			$identifier = \substr ( $packet, $offset, $len );
			$offset += $len;
			$len = \ord ( $packet {$offset ++} );
			$reason = \substr ( $packet, $offset, $len );
			// $this->instance->closeSession ( $identifier, $reason );
			$this->getLogger ()->info ( "IT IS CLOSE SESSION PACKET" );
		} elseif ($id === RakLib::PACKET_INVALID_SESSION) {
			$len = \ord ( $packet {$offset ++} );
			$identifier = \substr ( $packet, $offset, $len );
			// $this->instance->closeSession ( $identifier, "Invalid session" );
			$this->getLogger ()->info ( "IT IS INVALID_SESSION PACKET" );
		} elseif ($id === RakLib::PACKET_ACK_NOTIFICATION) {
			$len = \ord ( $packet {$offset ++} );
			$identifier = \substr ( $packet, $offset, $len );
			$offset += $len;
			$identifierACK = (\PHP_INT_SIZE === 8 ? \unpack ( "N", \substr ( $packet, $offset, 4 ) ) [1] << 32 >> 32 : \unpack ( "N", \substr ( $packet, $offset, 4 ) ) [1]);
			// $this->instance->notifyACK ( $identifier, $identifierACK );
			$this->getLogger ()->info ( "IT IS ACK_NOTIFICATION PACKET" );
		} else {
			$this->getLogger ()->info ( "UNKNOWN PACKET" );
		}
		
		return \true;
	}
	public function handleOption($name, $value) {
		if ($name === "bandwidth") {
			// $v = \unserialize($value);
			// $this->network->addStatistics($v["up"], $v["down"]);
			$this->getLogger ()->info ( "IT IS LOCAL BANDWIDTH PACKET" );
		}
	}
	public function handleRaw($address, $port, $payload) {
		try {
			// if (\strlen ( $payload ) > 2 and \substr ( $payload, 0, 2 ) === "\xfe\xfd") {
			$this->handleRawPacket ( $address, $port, $payload );
			// } else {
			// $this->getLogger ()->info ( "HANDLERAW PACKET IS WRONG?" );
			// }
		} catch ( \Exception $e ) {
			$this->getLogger ()->info ( "WRONG TYPE RAW PACKET?" );
		}
	}
	public function handleRawPacket($address, $port, $packet) {
		$offset = 2;
		$packetType = \ord ( $packet {$offset ++} );
		$sessionID = \unpack ( "N", \substr ( $packet, $offset, 4 ) ) [1] << 32 >> 32;
		$offset += 4;
		$payload = \substr ( $packet, $offset );
		
		switch ($packetType) {
			case self::HANDSHAKE : // Handshake
				$this->getLogger ()->info ( "IT IS HANDSHAKE PACKET" );
				break;
			case self::STATISTICS : // Stat
				$this->getLogger ()->info ( "IT IS STATISTICS PACKET" );
				break;
			default :
				$this->getLogger ()->info ( "UNKNOWN RAW PACKET" );
				break;
		}
	}
	public function handleEncapsulated($identifier, EncapsulatedPacket $packet, $flags) {
		try {
			if ($packet->buffer !== "") {
				$pk = $this->getPacket ( $packet->buffer );
				if ($pk !== \null) {
					$pk->decode ();
					$this->handlePacketProcess ( $pk );
				}
			}
		} catch ( \Exception $e ) {
			$this->getLogger ()->info ( "WRONG TYPE ENCAPSULATED PACKET?" );
		}
	}
	public function handlePacketProcess($packet) {
		if ($packet instanceof \pocketmine\network\protocol\DataPacket) {
			$packet->decode ();
			file_put_contents ( $this->getDataFolder () . "packet.txt", var_export ( $packet, true ) );
			$this->getLogger ()->info ( "User DataPacket Interpreted file has been saved" );
			return;
		}
		if ($packet::$ID >= 0x80 and $packet::$ID <= 0x8f and $packet instanceof DataPacket) { // Data packet
			$packets = [ ];
			$packet->decode ();
			foreach ( $packet->packets as $raklibPacket ) {
				echo "array foreach!\n";
				if ($packet->buffer !== "") {
					$packets [] = $raklibPacket;
				}
			}
			file_put_contents ( $this->getDataFolder () . "packet.txt", var_export ( $packets, true ) );
			$this->getLogger ()->info ( "Raklib DataPacket Interpreted file has been saved" );
		} else {
			if ($packet instanceof ACK) {
				$this->getLogger ()->info ( "IT IS ACK PACKET" );
				// $packet->decode ();
			} elseif ($packet instanceof NACK) {
				$this->getLogger ()->info ( "IT IS NACK PACKET" );
				// $packet->decode ();
			} else {
				$this->getLogger ()->info ( "Packet decode failed" );
			}
		}
	}
	/**
	 *
	 * @param EncapsulatedPacket $pk        	
	 * @param int $flags        	
	 */
	private function addToQueue(EncapsulatedPacket $pk, $flags = RakLib::PRIORITY_NORMAL) {
		$priority = $flags & 0b0000111;
		if ($pk->needACK and $pk->messageIndex !== \null) {
			$this->needACK [$pk->identifierACK] [$pk->messageIndex] = $pk->messageIndex;
		}
		if ($priority === RakLib::PRIORITY_IMMEDIATE) { // Skip queues
			$packet = new DATA_PACKET_0 ();
			$packet->seqNumber = $this->sendSeqNumber ++;
			if ($pk->needACK) {
				$packet->packets [] = clone $pk;
				$pk->needACK = \false;
			} else {
				$packet->packets [] = $pk->toBinary ();
			}
			
			$this->sendPacket ( $packet );
			$packet->sendTime = \microtime ( \true );
			$this->recoveryQueue [$packet->seqNumber] = $packet;
			
			return;
		}
		$length = $this->sendQueue->length ();
		if ($length + $pk->getTotalLength () > $this->mtuSize) {
			$this->sendQueue ();
		}
		
		if ($pk->needACK) {
			$this->sendQueue->packets [] = clone $pk;
			$pk->needACK = \false;
		} else {
			$this->sendQueue->packets [] = $pk->toBinary ();
		}
	}
	private function handleSplit(EncapsulatedPacket $packet) {
		if ($packet->splitCount >= 128) {
			return;
		}
		
		if (! isset ( $this->splitPackets [$packet->splitID] )) {
			$this->splitPackets [$packet->splitID] = [ 
					$packet->splitIndex => $packet 
			];
		} else {
			$this->splitPackets [$packet->splitID] [$packet->splitIndex] = $packet;
		}
		
		if (\count ( $this->splitPackets [$packet->splitID] ) === $packet->splitCount) {
			$pk = new EncapsulatedPacket ();
			$pk->buffer = "";
			for($i = 0; $i < $packet->splitCount; ++ $i) {
				$pk->buffer .= $this->splitPackets [$packet->splitID] [$i]->buffer;
			}
			
			$pk->length = \strlen ( $pk->buffer );
			unset ( $this->splitPackets [$packet->splitID] );
			
			$this->handleEncapsulatedPacketRoute ( $pk );
		}
	}
	private function handleEncapsulatedPacketRoute(EncapsulatedPacket $packet) {
		if ($packet->hasSplit) {
			$this->handleSplit ( $packet );
			return;
		}
		
		$id = \ord ( $packet->buffer {0} );
		if ($id < 0x80) { // internal data packet
			if ($this->state === self::STATE_CONNECTING_2) {
				if ($id === CLIENT_CONNECT_DataPacket::$ID) {
					$dataPacket = new CLIENT_CONNECT_DataPacket ();
					$dataPacket->buffer = $packet->buffer;
					$dataPacket->decode ();
					$pk = new SERVER_HANDSHAKE_DataPacket ();
					$pk->address = $this->address;
					$pk->port = $this->port;
					$pk->sendPing = $dataPacket->sendPing;
					$pk->sendPong = \bcadd ( $pk->sendPing, "1000" );
					$pk->encode ();
					
					$sendPacket = new EncapsulatedPacket ();
					$sendPacket->reliability = 0;
					$sendPacket->buffer = $pk->buffer;
					$this->addToQueue ( $sendPacket, RakLib::PRIORITY_IMMEDIATE );
				} elseif ($id === CLIENT_HANDSHAKE_DataPacket::$ID) {
					$dataPacket = new CLIENT_HANDSHAKE_DataPacket ();
					$dataPacket->buffer = $packet->buffer;
					$dataPacket->decode ();
					
					if ($dataPacket->port === $this->sessionManager->getPort () or ! $this->sessionManager->portChecking) {
						$this->state = self::STATE_CONNECTED; // FINALLY!
						$this->sessionManager->openSession ( $this );
						foreach ( $this->preJoinQueue as $p ) {
							$this->sessionManager->streamEncapsulated ( $this, $p );
						}
						$this->preJoinQueue = [ ];
					}
				}
			} elseif ($id === CLIENT_DISCONNECT_DataPacket::$ID) {
				$this->disconnect ( "client disconnect" );
			} elseif ($id === PING_DataPacket::$ID) {
				$dataPacket = new PING_DataPacket ();
				$dataPacket->buffer = $packet->buffer;
				$dataPacket->decode ();
				
				$pk = new PONG_DataPacket ();
				$pk->pingID = $dataPacket->pingID;
				$pk->encode ();
				
				$sendPacket = new EncapsulatedPacket ();
				$sendPacket->reliability = 0;
				$sendPacket->buffer = $pk->buffer;
				$this->addToQueue ( $sendPacket );
			} // TODO: add PING/PONG (0x00/0x03) automatic latency measure
		} elseif ($this->state === self::STATE_CONNECTED) {
			$this->sessionManager->streamEncapsulated ( $this, $packet );
			
			// TODO: stream channels
		} else {
			$this->preJoinQueue [] = $packet;
		}
	}
	private function handleEncapsulatedPacket(EncapsulatedPacket $packet) {
		if ($packet->messageIndex === \null) {
			$this->handleEncapsulatedPacketRoute ( $packet );
		} else {
			$this->handleEncapsulatedPacketRoute ( $packet );
			
			if (\count ( $this->reliableWindow ) > 0) {
				\ksort ( $this->reliableWindow );
				
				foreach ( $this->reliableWindow as $index => $pk ) {
					if (($index - $this->lastReliableIndex) !== 1) {
						break;
					}
					$this->lastReliableIndex ++;
					$this->reliableWindowStart ++;
					$this->reliableWindowEnd ++;
					$this->handleEncapsulatedPacketRoute ( $pk );
					unset ( $this->reliableWindow [$index] );
				}
			}
		}
	}
	/**
	 *
	 * @param
	 *        	$id
	 *        	
	 * @return Packet
	 */
	public function getPacketFromPool($id) {
		if (isset ( $this->packetPool [$id] )) {
			return clone $this->packetPool [$id];
		}
		
		return \null;
	}
	private function getPacket($buffer) {
		$pid = \ord ( $buffer {0} );
		$this->getLogger ()->info ( "PID IS 0x" . dechex ( $pid ) );
		
		if (($data = $this->getServer ()->getNetwork ()->getPacket ( $pid )) === \null) {
			return \null;
		}
		$data->setBuffer ( $buffer, 1 );
		
		return $data;
	}
	private function registerPacket($id, $class) {
		$this->packetPool [$id] = new $class ();
	}
	private function registerPackets() {
		// $this->registerPacket(UNCONNECTED_PING::$ID, UNCONNECTED_PING::class);
		$this->registerPacket ( UNCONNECTED_PING_OPEN_CONNECTIONS::$ID, UNCONNECTED_PING_OPEN_CONNECTIONS::class );
		$this->registerPacket ( OPEN_CONNECTION_REQUEST_1::$ID, OPEN_CONNECTION_REQUEST_1::class );
		$this->registerPacket ( OPEN_CONNECTION_REPLY_1::$ID, OPEN_CONNECTION_REPLY_1::class );
		$this->registerPacket ( OPEN_CONNECTION_REQUEST_2::$ID, OPEN_CONNECTION_REQUEST_2::class );
		$this->registerPacket ( OPEN_CONNECTION_REPLY_2::$ID, OPEN_CONNECTION_REPLY_2::class );
		$this->registerPacket ( UNCONNECTED_PONG::$ID, UNCONNECTED_PONG::class );
		$this->registerPacket ( ADVERTISE_SYSTEM::$ID, ADVERTISE_SYSTEM::class );
		$this->registerPacket ( DATA_PACKET_0::$ID, DATA_PACKET_0::class );
		$this->registerPacket ( DATA_PACKET_1::$ID, DATA_PACKET_1::class );
		$this->registerPacket ( DATA_PACKET_2::$ID, DATA_PACKET_2::class );
		$this->registerPacket ( DATA_PACKET_3::$ID, DATA_PACKET_3::class );
		$this->registerPacket ( DATA_PACKET_4::$ID, DATA_PACKET_4::class );
		$this->registerPacket ( DATA_PACKET_5::$ID, DATA_PACKET_5::class );
		$this->registerPacket ( DATA_PACKET_6::$ID, DATA_PACKET_6::class );
		$this->registerPacket ( DATA_PACKET_7::$ID, DATA_PACKET_7::class );
		$this->registerPacket ( DATA_PACKET_8::$ID, DATA_PACKET_8::class );
		$this->registerPacket ( DATA_PACKET_9::$ID, DATA_PACKET_9::class );
		$this->registerPacket ( DATA_PACKET_A::$ID, DATA_PACKET_A::class );
		$this->registerPacket ( DATA_PACKET_B::$ID, DATA_PACKET_B::class );
		$this->registerPacket ( DATA_PACKET_C::$ID, DATA_PACKET_C::class );
		$this->registerPacket ( DATA_PACKET_D::$ID, DATA_PACKET_D::class );
		$this->registerPacket ( DATA_PACKET_E::$ID, DATA_PACKET_E::class );
		$this->registerPacket ( DATA_PACKET_F::$ID, DATA_PACKET_F::class );
		$this->registerPacket ( NACK::$ID, NACK::class );
		$this->registerPacket ( ACK::$ID, ACK::class );
	}
	private function strToHex($string) {
		$hex = '';
		for($i = 0; $i < strlen ( $string ); $i ++) {
			$ord = ord ( $string [$i] );
			$hexCode = dechex ( $ord );
			$hex .= substr ( '0' . $hexCode, - 2 );
		}
		return strToUpper ( $hex );
	}
	private function hexToStr($hex) {
		$string = '';
		for($i = 0; $i < strlen ( $hex ) - 1; $i += 2) {
			$string .= chr ( hexdec ( $hex [$i] . $hex [$i + 1] ) );
		}
		return $string;
	}
}

?>