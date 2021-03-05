# One-Click Miner with One-Click Submarine Swap

This is an **EXPERIMENTAL**, unprecedented software! (i.e. don't put in what you can't afford to lose!)

This One-Click Miner version is based on upstream: [https://github.com/vertcoin-project/one-click-miner-vnext](https://github.com/vertcoin-project/one-click-miner-vnext)

It allows you to swap Vertcoin into LN Bitcoin with a minimal effort.

This software is available for Windows and Linux.

## HOWTO (Read This Carefully!)

### Prerequisites

Unpack .zip archive and move `wifi` folder into vertcoin-ocm directory. The correct path should look like this: `%AppData%\vertcoin-ocm\wifi`

Unlock your port `5890` on firewall for inbound connections: ["How do I open a port on windows firewall"](https://www.howtogeek.com/394735/how-do-i-open-a-port-on-windows-firewall/)

Strongly recommended Lightning Network wallet is: [LN Phoenix Wallet](https://phoenix.acinq.co/) from ACINQ (["wen iOS"](https://medium.com/@ACINQ/when-ios-cdf798d5f8ef))

Strongly recommended web browser is: Chrome

### Start

Allow OCM in Antivirus/Windows Defender: [Youtube Howto](https://youtu.be/V2uqtXBeKgM?t=129)

Run OCM and search in `debug.log` for IP address of your mining rig: `"Connect your mobile phone to: https://x.x.x.x:5890/"`

Connect your web browser to this URL and accept all questions. Both your rig and your smartphone - must be in the same local network.

### Submarine Swap

You should see the green screen with some basic informations from OCM. Wait for non-zero values.

If you have more than **100 inputs** received from your pool (like in this example: [VrSwsBBq6TgsAyy8YQdes4we49o6KyiqFU](https://insight.vertcoin.org/insight-vtc-api/addr/VrSwsBBq6TgsAyy8YQdes4we49o6KyiqFU/utxo)) - aggregate it first! Simply paste your own OCM address in `Receiver Address` field, enter your password and press `Send`. After next Vertcoin block ([http://insight.vertcoin.org/](http://insight.vertcoin.org/)) - click on `Reload` icon. You can go ahead once you see it back in Spendable Balance.

In your Phoenix Wallet press `Receive`, then press small `Edit` icon (with square and pen) and type **10,000 sat**. This is the required initial amount in case of freshly installed, non-active yet Phoenix Wallet. Then press `Create invoice` and tap in QR code to copy LN invoice into clipboard (to unlock initial amount in case you already have an active, non-zero balance LN wallet - please visit our [#one-click-miner-help](https://discord.gg/vertcoin)).

Go back to the previous screen (`https://x.x.x.x:5890/`) and paste the LN Invoice from a clipboard using the upper button. Enter your OCM wallet password and press `Submarine Swap`. Wait a second to get confirmation, then a few seconds later to open the prepared link to the Submarine transaction (Insight may be slower than you). After single confirmation (averages 2.5 minutes) you should see the new payment in your LN Wallet. However, if it has failed for any reason, **funds are SAFU!** A great testing feature of LN network is a contract will expire and six hours later the refund transaction should be sent automatically to your OCM native SegWit address (not supported in OCM yet). If none of these are present after six hours - backup your `redeem.txt/redeem.old` files and report it here: [#one-click-miner-help](https://discord.gg/vertcoin).

So only in case of refund - you will need the OCM private key: after start simply leave an empty `Receiver Address` field and correct password in OCM and press `Send`, then `Retry`. Now you can copy/paste your WIF private key in Linux or: rewrite letter by letter in Windows ;)

Due to refunding procedure - the next swap can be executed after six hours. From this moment minimum swap is 100 sat, maximum is 100,000 sat. For simplicity swaps are processed in increments of 100 sats per transaction.

Right after submarine swap you will see zero amount in Spendable Balance of OCM. After next Vertcoin block click on `Reload` icon to update it.

Submarine instance is based on open source project: [https://github.com/BoltzExchange](https://github.com/BoltzExchange). You can try some other swap options here: [Boltz Exchange](https://boltz.exchange/)

Want to follow along with us? Check out this video on the step by step process of setting up One-Click Miner with Submarine Swap: [https://youtu.be/YKvw0q6_yhY](https://youtu.be/YKvw0q6_yhY)

## FAQ

### Which GPUs are supported?

Please refer to this list of [supported hardware.](https://github.com/CryptoGraphics/VerthashMiner#supported-hardware)

### I have an error message that reads 'Failure to configure'

You may need to add an exclusion to your antivirus / Windows Defender.

### My GPU is supported but an error messages reads 'no compatible GPUs'

Update your GPU drivers to the latest version.


## Building

The GUI of this MVP is based on [Wails](https://wails.app) and [Go](https://golang.org/).

Install the Wails [prerequisites](https://wails.app/home.html#prerequisites) for your platform, and then run:

```bash
go get github.com/wailsapp/wails/cmd/wails
```

Then clone this repository, and inside its main folder, execute:

```bash
wails build
```

## Donations

If you want to support the further development of the One Click Miner, feel free to donate Vertcoin to [Vmnbtn5nnNbs1otuYa2LGBtEyFuarFY1f8](https://insight.vertcoin.org/address/Vmnbtn5nnNbs1otuYa2LGBtEyFuarFY1f8).
