async function Start() {
	const crypto = require('crypto');
	const Mnemonic = require('bitcore-mnemonic');
	const Bitcore = require('bitcore-lib');
	const minimist = require('minimist');

	let args = minimist(process.argv.slice(2), {
		default: {
			limit: 20
		},
	});


	function passphraseOfSeedHandle(onDone) {
		const rl = require('readline').createInterface({
			input: process.stdin,
			output: process.stdout
		});
		const fs = require('fs');

		fs.readFile('keys.json', 'utf8', (err, keysData) => {
			if(err) {
				rl.question('Please insert seed words in line: ', (seedData) => {
					seedData = !seedData ? require('os').hostname() || 'Headless' : seedData;
					rl.question('Please insert passphrase: ', (passphraseData) => {
						rl.close();

						if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
						if (process.stdout.clearLine) process.stdout.clearLine();
						let deviceTempPrivKey = crypto.randomBytes(32);
						let devicePrevTempPrivKey = crypto.randomBytes(32);

						let mnemonic = new Mnemonic();

						if (!Mnemonic.isValid(mnemonic.toString()))
							throw new Error("Incorrect mnemonica validation");

						fs.writeFile('keys.json', JSON.stringify({
							mnemonic_phrase: seedData,
							temp_priv_key: deviceTempPrivKey.toString('base64'),
							prev_temp_priv_key: devicePrevTempPrivKey.toString('base64')
						}, null, '\t'), function (err) {
							if (err)
								throw Error("failed to write keys file");

						});
					});
				});
			}

			else
			{
				rl.question('passphrase: ', (passphraseData) => {
					rl.close();

					if (process.stdout.moveCursor) process.stdout.moveCursor(0, -1);
					if (process.stdout.clearLine) process.stdout.clearLine();

					let keys = JSON.parse(keysData);

					let deviceTempPrivKey = Buffer(keys.temp_priv_key, 'base64');
					let devicePrevTempPrivKey = Buffer(keys.prev_temp_priv_key, 'base64');

					onDone(keys.mnemonic_phrase, passphraseData, deviceTempPrivKey, devicePrevTempPrivKey);
				});
			}
		});
	}


	passphraseOfSeedHandle((mnemonic_phrase, passphrase) => {
		const async = require('async');
		const conf = require('byteballcore/conf.js');
		const wallet_defined_by_keys = require('byteballcore/wallet_defined_by_keys.js');
		const objectHash = require('byteballcore/object_hash.js');
		const db = require('byteballcore/db.js');
		const network = require('byteballcore/network');
		const myWitnesses = require('byteballcore/my_witnesses');

		let assocIndexesToWallets = [];

		let mnemonic = new Mnemonic(mnemonic_phrase);
		let xPrivKey = mnemonic.toHDPrivateKey(passphrase);

		function createAddresses(assocMaxAddressIndexes, cb) {
			function addAddress(wallet, is_change, index, maxIndex) {
				wallet_defined_by_keys.issueAddress(wallet, is_change, index, function () {
					index++;
					if (index <= maxIndex) {
						addAddress(wallet, is_change, index, maxIndex);
					} else {
						if (is_change) {
							cb();
						}
						else {
							startAddToNewWallet(1);
						}
					}
				});
			}

			function startAddToNewWallet(is_change) {
				if (is_change) {
					if (assocMaxAddressIndexes[0].change !== undefined) {
						addAddress(assocIndexesToWallets[0], 1, 0, assocMaxAddressIndexes[0].change);
					} else {
						cb();
					}
				} else {
					addAddress(assocIndexesToWallets[0], 0, 0, 0);
				}
			}

			startAddToNewWallet(0);
		}

		function createWallets(arrWalletIndexes, assocMaxAddressIndexes, cb) {
			function createWallet(n) {
				let devicePrivKey = xPrivKey.derive("m/1'").privateKey.bn.toBuffer({size: 32});
				let device = require('byteballcore/device.js');
				device.setDevicePrivateKey(devicePrivKey);
				let strXPubKey = Bitcore.HDPublicKey(xPrivKey.derive("m/44'/0'/0'")).toString();
				let walletDefinedByKeys = require('byteballcore/wallet_defined_by_keys.js');
				walletDefinedByKeys.createWalletByDevices(strXPubKey, 0, 1, [], 'any walletName', false, (wallet_id) => {
					walletDefinedByKeys.issueNextAddress(wallet_id, 0, () => {
						assocIndexesToWallets[0] = wallet_id;
						cb();
					});
				});
			}

			createWallet(0);
		}

		function determineIfAddressUsed(address, cb) {
			db.query("SELECT 1 FROM outputs WHERE address = ? LIMIT 1", [address], function(outputsRows) {
				if (outputsRows.length === 1)
					cb(true);
				else {
					db.query("SELECT 1 FROM unit_authors WHERE address = ? LIMIT 1", [address], function(unitAuthorsRows) {
						cb(unitAuthorsRows.length === 1);
					});
				}
			});
		}


		function removeAddressesAndWallets(cb) {
			var arrQueries = [];
			db.addQuery(arrQueries, "DELETE FROM pending_shared_address_signing_paths");
			db.addQuery(arrQueries, "DELETE FROM shared_address_signing_paths");
			db.addQuery(arrQueries, "DELETE FROM pending_shared_addresses");
			db.addQuery(arrQueries, "DELETE FROM shared_addresses");
			db.addQuery(arrQueries, "DELETE FROM my_addresses");
			db.addQuery(arrQueries, "DELETE FROM wallet_signing_paths");
			db.addQuery(arrQueries, "DELETE FROM extended_pubkeys");
			db.addQuery(arrQueries, "DELETE FROM wallets");
			db.addQuery(arrQueries, "DELETE FROM correspondent_devices");

			async.series(arrQueries, cb);
		}

		function cleanAndAddWalletsAndAddresses(assocMaxAddressIndexes) {
			let device = require('byteballcore/device');
			let arrWalletIndexes = Object.keys(assocMaxAddressIndexes);
			if (arrWalletIndexes.length) {
				removeAddressesAndWallets(function () {
					device.setDevicePrivateKey(xPrivKey.derive("m/1'").privateKey.bn.toBuffer({size: 32}));
					createWallets(arrWalletIndexes, assocMaxAddressIndexes, function () {
						createAddresses(assocMaxAddressIndexes, function () {
							console.log('wallet recovered, please restart the application');
							process.exit();
						});
					});
				});
			} else {
				throw Error('No active addresses found.');
			}
		}

		function scanForAddressesAndWallets(mnemonic, cb) {
			let xPubKey;
			let lastUsedAddressIndex = -1;
			let lastUsedWalletIndex = -1;
			let currentAddressIndex = 0;
			let currentWalletIndex = 0;
			let assocMaxAddressIndexes = {};

			function checkAndAddCurrentAddress(is_change) {
				let address = objectHash.getChash160(["sig", {"pubkey": wallet_defined_by_keys.derivePubkey(xPubKey, 'm/' + is_change + '/' + currentAddressIndex)}]);
				determineIfAddressUsed(address, function (bUsed) {
					if (bUsed) {
						lastUsedAddressIndex = currentAddressIndex;
						if (!assocMaxAddressIndexes[currentWalletIndex]) assocMaxAddressIndexes[currentWalletIndex] = {main: 0};
						if (is_change) {
							assocMaxAddressIndexes[currentWalletIndex].change = currentAddressIndex;
						} else {
							assocMaxAddressIndexes[currentWalletIndex].main = currentAddressIndex;
						}
						currentAddressIndex++;
						checkAndAddCurrentAddress(is_change);
					} else {
						currentAddressIndex++;
						if (currentAddressIndex - lastUsedAddressIndex >= args.limit) {
							if (is_change) {
								if (lastUsedAddressIndex !== -1) {
									lastUsedWalletIndex = currentWalletIndex;
								}
								if (currentWalletIndex - lastUsedWalletIndex >= args.limit) {
									cb(assocMaxAddressIndexes);
								} else {
									currentWalletIndex++;
									setCurrentWallet();
								}
							} else {
								currentAddressIndex = 0;
								checkAndAddCurrentAddress(1);
							}
						} else {
							checkAndAddCurrentAddress(is_change);
						}
					}
				})
			}

			function setCurrentWallet() {
				xPubKey = Bitcore.HDPublicKey(xPrivKey.derive("m/44'/0'/" + currentWalletIndex + "'"));
				lastUsedAddressIndex = -1;
				currentAddressIndex = 0;
				checkAndAddCurrentAddress(0);
			}

			setCurrentWallet();
		}
		function scanForAddressesAndWalletsInLightClient(mnemonic, cb) {
			let lastUsedWalletIndex = -1;
			let assocMaxAddressIndexes = {};
			let xPubKey = null;

			function checkAndAddCurrentAddresses(is_change) {
				let type = is_change ? 'change' : 'main';
				let batchSize = assocMaxAddressIndexes[0] ? args.limit : 1;
				if (!assocMaxAddressIndexes[0])
					assocMaxAddressIndexes[0] = {};
				let arrTmpAddresses = [];
				let startIndex = (assocMaxAddressIndexes[0][type] === undefined) ? 0 : (assocMaxAddressIndexes[0][type] + 1);
				for (let i = 0; i < batchSize; i++) {
					let index = startIndex + i;
					arrTmpAddresses.push(objectHash.getChash160(["sig", {"pubkey": wallet_defined_by_keys.derivePubkey(xPubKey, 'm/0/' + index)}]));
				}

				myWitnesses.readMyWitnesses(function (arrWitnesses) {
					network.requestFromLightVendor('light/get_history', {
						addresses: arrTmpAddresses,
						witnesses: arrWitnesses
					}, function (ws, request, response) {
						if (response && response.error) {
							throw Error('When scanning an error occurred, please try again later.');
						}
						if (Object.keys(response).length) {
							lastUsedWalletIndex = 0;
							assocMaxAddressIndexes[0][type] = startIndex + batchSize - 1;
							checkAndAddCurrentAddresses(is_change);
						} else {
							if (is_change) {
								if (assocMaxAddressIndexes[0].change === undefined && assocMaxAddressIndexes[0].main === undefined)
									delete assocMaxAddressIndexes[0];
								cb(assocMaxAddressIndexes);
							} else {
								checkAndAddCurrentAddresses(1);
							}
						}
					});
				}, 'wait');
			}

			function setCurrentWallet() {
				xPubKey = Bitcore.HDPublicKey(xPrivKey.derive("m/44'/0'/0'"));
				checkAndAddCurrentAddresses(0);
			}

			setCurrentWallet();
		}

		if (conf.bLight) {
			require('byteballcore/light_wallet.js').setLightVendorHost(conf.hub);
			scanForAddressesAndWalletsInLightClient(mnemonic_phrase, cleanAndAddWalletsAndAddresses);
		}

		else
			scanForAddressesAndWallets(mnemonic_phrase, cleanAndAddWalletsAndAddresses)

	});

	return 'Ok';
}

Start().then(console.log).catch(console.error);