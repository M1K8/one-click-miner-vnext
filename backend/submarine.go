package backend

import (
	"fmt"
	"net/http"
	"log"
	"io/ioutil"
	"encoding/json"
	"strconv"
	"math"
	"os"
        "path/filepath"
	"bufio"
	"strings"
	"time"
	"net"
	"encoding/hex"
	"bytes"
	"crypto/sha256"

	"github.com/vertcoin-project/one-click-miner-vnext/logging"
	"github.com/vertcoin-project/one-click-miner-vnext/util"
	"github.com/vertcoin-project/one-click-miner-vnext/keyfile"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcd/txscript"
)

type Bittrex struct {
        Bid []struct {
                Quantity string `json:"quantity"`
                Rate     string `json:"rate"`
        } `json:"bid"`
        Ask []struct {
                Quantity string `json:"quantity"`
                Rate     string `json:"rate"`
        } `json:"ask"`
}

type CreateSwap struct {
        Type            string `json:"type"`
        PairID          string `json:"pairId"`
        OrderSide       string `json:"orderSide"`
        Invoice         string `json:"invoice"`
        RefundPublicKey string `json:"refundPublicKey"`
}

type CreateResponse struct {
        ID                 string `json:"id"`
        Bip21              string `json:"bip21"`
        Address            string `json:"address"`
        RedeemScript       string `json:"redeemScript"`
        AcceptZeroConf     bool   `json:"acceptZeroConf"`
        ExpectedAmount     int    `json:"expectedAmount"`
        TimeoutBlockHeight int    `json:"timeoutBlockHeight"`
        Error              string `json:"error"`
}

type OutputType int

const (
        SegWit OutputType = iota
        Compatibility
        Legacy
)

type OutputDetails struct {
        LockupTransaction *btcutil.Tx
        Vout              uint32
        OutputType        OutputType

        RedeemScript []byte
        PrivateKey   *btcec.PrivateKey
        // Should be set to an empty array in case of a refund
        Preimage []byte
        TimeoutBlockHeight uint32
}

func GenerateIndexHtml(vtc_bal, vtc_ee, w_hr float64) (int64) {
	var tmpstr string
	sat_max, vtc_max, err := BittrexGet(vtc_bal)
	if err != nil { logging.Errorf("BittrexGet error: %s", err) }

	indexPath := filepath.Join(util.DataDirectory(), "wifi/public_html/index.html")
	f, err := os.OpenFile(indexPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil { logging.Errorf("OpenFile Error: %s", err) }

	f.WriteString("<html><head><meta charset=\"UTF-8\" name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"refresh\" content=\"60\"></head><body style=\"background-color:#0d6e48;\"><center><h3 style=\"color:white;\"><br>Spendable Balance: ")
	tmpstr = fmt.Sprintf("%.3f", vtc_bal)
	f.WriteString(tmpstr)

	f.WriteString(" VTC<br><br>Expected Earnings (24h):<br>~")
	tmpstr = fmt.Sprintf("%.3f", vtc_ee)
	f.WriteString(tmpstr)

	f.WriteString(" VTC (")

	w_hr /= 1000
	tmpstr = fmt.Sprintf("%.3f", w_hr)
	f.WriteString(tmpstr)

	f.WriteString(" MH/s)<br><br>You can swap: ")
	tmpstr = fmt.Sprintf("%.3f", vtc_max)
	f.WriteString(tmpstr)

	//m.gsat_max = sat_max
	f.WriteString(" VTC<br>into: ")
	tmpstr = fmt.Sprintf("%d", sat_max)
	f.WriteString(tmpstr)
	f.WriteString(" sat</h3><br><button onclick=\"myCopy()\">Paste from clipboard</button><br><br><form method=\"POST\" action=\"/form\"><textarea name=\"invoice\" class=\"js-cuttextarea\">Press button above to copy LN invoice</textarea><br><br><br><br><input type=\"texti\" name=\"ocm_pass\" size=\"8\" placeholder=\"OCM password\" required><br><br><input type=\"submit\" value=\"Submarine Swap\"></form><br>")
	if w_hr > 0 {
		f.WriteString("<img src=\"on_64.png\">")
	} else {
		f.WriteString("<img src=\"off_64.png\">")
	}
	f.WriteString("</center><script>function myCopy() { var pasteTextarea = document.querySelector('.js-cuttextarea'); navigator.clipboard.readText().then((text) => { pasteTextarea.textContent = text; log('LN invoice: ' + text); }).catch((err) => log('Async readText failed with error: \"' + err + '\"')); }</script></body></html>")

	err = f.Close();
	if err != nil { logging.Errorf("Close error: %s", err) }

	return sat_max
}

func TryRedeem() (string, error) {
	//if redeem.txt exist, read the content; if over 6h - try to redeem and rotate files
	redeemtxtPath := filepath.Join(util.DataDirectory(), "wifi/redeem.txt")
	redeemoldPath := filepath.Join(util.DataDirectory(), "wifi/redeem.old")

	if _, err := os.Stat(redeemtxtPath); err == nil {
		f, err := os.Open(redeemtxtPath)
		if err != nil { return "", err }

		reader := bufio.NewReader(f)
		var line string
		line, err = reader.ReadString('\n')
		err = f.Close();
		if err != nil { logging.Errorf("Close error: %s", err) }

		redeem_str := strings.Split(line, ";")
		sec_then, err := strconv.ParseInt(redeem_str[0], 10, 64)
		if err != nil { logging.Errorf("Parse error: %s", err) }

		t := time.Now()
		sec_now := t.Unix()

		if (sec_now - sec_then) > 21600 {
			err := os.Rename(redeemtxtPath, redeemoldPath)
			if err != nil { log.Fatal(err) }

			return redeem_str[8], nil
		}
	}

	return "", nil
}

func (m *Backend) RunHttpsServer() {
	conn, err := net.Dial("udp", "8.8.8.8:80")
        if err != nil { logging.Errorf("No internet connection...\n") }
        defer conn.Close()
        localAddr := conn.LocalAddr().(*net.UDPAddr)
        localIP := localAddr.IP.String()

        httpDirPath := filepath.Join(util.DataDirectory(), "wifi/public_html")
        fileServer := http.FileServer(http.Dir(httpDirPath))
        http.Handle("/", fileServer)
        http.HandleFunc("/form", m.formHandler)
        crtPath := filepath.Join(util.DataDirectory(), "wifi/https-server.crt")
        keyPath := filepath.Join(util.DataDirectory(), "wifi/https-server.key")

        logging.Infof("Connect your mobile phone to: https://%s:5890/\n", localIP)
        err = http.ListenAndServeTLS(":5890", crtPath, keyPath, nil) //https server
        if err != nil { logging.Errorf("Opening port 5890 is failed...\n") }
}

func BittrexGet(x float64) (int64, float64, error) {
        resp, err := http.Get("https://api.bittrex.com/v3/markets/VTC-BTC/orderbook")
        if err != nil { log.Fatalln(err) }
        defer resp.Body.Close()
        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        var bittrexStruct Bittrex
        json.Unmarshal(bodyBytes, &bittrexStruct)

        var sum_vtc, sum_btc, round_btc, round_sat_f float64
        var round_sat int64

        // discover amount of satoshi using x VTC
        for i := 0; i< len(bittrexStruct.Bid); i++ {
                vtc, err := strconv.ParseFloat(bittrexStruct.Bid[i].Quantity, 64)
                if err != nil { logging.Errorf("Parse error: %s", err) }

                rate, err := strconv.ParseFloat(bittrexStruct.Bid[i].Rate, 64)
                if err != nil { logging.Errorf("Parse error: %s", err) }

                sum_vtc += vtc
                if sum_vtc > x {
                        sum_btc = x * rate * 0.995
                        round_sat_f = math.Floor(sum_btc*1000000)*100
                        break
                }
                sum_btc = sum_vtc * rate
        }

        // discover amount of VTC using round_sat_f
        sum_vtc = 0
        sum_btc = 0
        round_btc = round_sat_f / 100000000

        for i := 0; i< len(bittrexStruct.Bid); i++ {
                vtc, err := strconv.ParseFloat(bittrexStruct.Bid[i].Quantity, 64)
                if err != nil { logging.Errorf("Parse error: %s", err) }

                rate, err := strconv.ParseFloat(bittrexStruct.Bid[i].Rate, 64)
                if err != nil { logging.Errorf("Parse error: %s", err) }

                sum_vtc += vtc
                sum_btc = sum_vtc * rate
                if sum_btc > round_btc {
                        sum_vtc = round_btc / (rate * 0.995)
                        sum_vtc = math.Ceil(sum_vtc*1000)/1000
                        break
                }
        }

        round_sat = int64(round_sat_f)
        return round_sat, sum_vtc, nil
}

func (m *Backend) formHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
                logging.Errorf("ParseForm error\n")
                return
        }
        invoice := r.FormValue("invoice")
        ocm_pass := r.FormValue("ocm_pass")
        logging.Infof("Invoice: %s\n", invoice)

        // start html response
        fmt.Fprintf(w, "<html><head><meta charset=\"UTF-8\" name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body style=\"background-color:#0b5c3c;\"><center><h3 style=\"color:white;\"><br>")

	if m.gsat_max == 0 {
		fmt.Fprintf(w, "Too low Spendable Balance")
		fmt.Fprintf(w, endHtml())
		return
	}

	redeemPath := filepath.Join(util.DataDirectory(), "wifi/redeem.txt")
	if _, err := os.Stat(redeemPath); err == nil {
		fmt.Fprintf(w, "Wait six hours before your next swap")
		fmt.Fprintf(w, endHtml())
		return
	}

        if !strings.HasPrefix(invoice, "lnbc") {
                fmt.Fprintf(w, "Incorrect LN invoice syntax")
		fmt.Fprintf(w, endHtml())
		return
	}

	if strings.HasPrefix(invoice, "lnbc1p") {
		fmt.Fprintf(w, "Zero-amount LN invoice<br><br>Not suitable for submarine swap")
		fmt.Fprintf(w, endHtml())
		return
	}

	s1 := strings.Split(invoice, "1p")
	s2 := strings.Split(s1[0], "lnbc")

	if ( strings.HasSuffix(s2[1], "p") || strings.HasSuffix(s2[1], "n") ) {
		fmt.Fprintf(w, "Please use a multiple of 100 sat")
		fmt.Fprintf(w, endHtml())
		return
	}

	var sat_inv int64
	if strings.HasSuffix(s2[1], "u") {
		s3 := strings.Split(s2[1], "u")
		u_sat, err := strconv.ParseInt(s3[0], 10, 64)
		if err != nil { logging.Errorf("Parse error: %s\n", err) }
		sat_inv = u_sat * 100
	}
	if strings.HasSuffix(s2[1], "m") {
		s3 := strings.Split(s2[1], "m")
		m_sat, err := strconv.ParseInt(s3[0], 10, 64)
		if err != nil { logging.Errorf("Parse error: %s\n", err) }
		sat_inv = m_sat * 100000
	}

	redeemOld := filepath.Join(util.DataDirectory(), "wifi/redeem.old")
	if _, err := os.Stat(redeemOld); (err != nil && sat_inv < 10000 ) {
		fmt.Fprintf(w, "Initial top-up of Phoenix Wallet must be at least 10,000 sat")
		fmt.Fprintf(w, endHtml())
		return
	}

	if sat_inv > 100000 {
		fmt.Fprintf(w, "Please use up to 100,000 sat")
		fmt.Fprintf(w, endHtml())
		return
	}

	var tmpstr string
	if sat_inv > m.gsat_max {
		fmt.Fprintf(w, "Not enough funds for: ")
		tmpstr = fmt.Sprintf("%d", sat_inv)
		fmt.Fprintf(w, tmpstr)
		fmt.Fprintf(w, " sat<br><br>Max is: ")
		tmpstr := fmt.Sprintf("%d", m.gsat_max)
		fmt.Fprintf(w, tmpstr)
		fmt.Fprintf(w, " sat")
		fmt.Fprintf(w, endHtml())
		return
	}

	if !keyfile.TestPassword(ocm_pass) {
		fmt.Fprintf(w, "Wrong OCM password")
		fmt.Fprintf(w, endHtml())
		return
	}

	pubkey := keyfile.GetPublicKey()
	hex_pubkey := hex.EncodeToString(pubkey)

	text_sp, addr_sp, err := SubPost(invoice, hex_pubkey)
	if err != nil {
		fmt.Fprintf(w, addr_sp)
		fmt.Fprintf(w, endHtml())
		return
	}

	if strings.HasPrefix(text_sp, "Err") {
		fmt.Fprintf(w, addr_sp)
		fmt.Fprintf(w, endHtml())
		return
	}

	vtc_inv, err := strconv.ParseInt(text_sp, 10, 64)
	if err != nil { logging.Errorf("Parse error: %s\n", err) }

	m.PrepareSweepSub(vtc_inv, addr_sp)
	txid := m.SendSweepSub(ocm_pass)

	amount_f := float64(vtc_inv)
	amount_f /= 100000000

	tmpstr = fmt.Sprintf("%.3f", amount_f)
	fmt.Fprintf(w, tmpstr)
	fmt.Fprintf(w, " VTC swapped for ")
	tmpstr = fmt.Sprintf("%d", sat_inv)
	fmt.Fprintf(w, tmpstr)
	fmt.Fprintf(w, " sat!<br><br>Your LN Wallet will be top-up soon<br><br>")
	fmt.Fprintf(w, "<br>Check your TXID <a href=\"https://insight.vertcoin.org/tx/")
	fmt.Fprintf(w, txid[0])
	fmt.Fprintf(w, "\" target=\"_blank\">here</a>")

	fmt.Fprintf(w, endHtml())
	return
}

func endHtml() string {
	return "</h3><br><br><button onclick=\"goBack()\">Back</button><script> function goBack() { window.history.back(); } </script></center></body></html>\n"
}

func SubPost(s_invoice string, s_refpubkey string) (string, string, error) {
        create_swap := CreateSwap{"submarine", "VTC/BTC", "sell", s_invoice, s_refpubkey}
        jsonReq, err := json.Marshal(create_swap)

        resp, err := http.Post("http://161.97.127.179:5890/createswap", "application/json", bytes.NewBuffer(jsonReq))
        if err != nil {
                logging.Errorf("Boltz instance error\n")
		return "Error: ", "Boltz instance error", err
	}

        defer resp.Body.Close()
        bodyBytes, _ := ioutil.ReadAll(resp.Body)

        var cs_response CreateResponse
        json.Unmarshal(bodyBytes, &cs_response)

	resp_len := len(cs_response.Error)
        if resp_len > 0 {
                logging.Errorf("Boltz response error: %s\n", cs_response.Error)
		return "Error: ", cs_response.Error, nil
	} else if cs_response.ExpectedAmount == 0 {
                logging.Errorf("Boltz error\n")
		return "Error: ", "Boltz error", nil
        } else {
                // TODO verify if cs_response.Address is the submarine address
                //if address OK
                //
                        //write data to redeem.txt
                        redeemPath := filepath.Join(util.DataDirectory(), "wifi/redeem.txt")
                        f, err := os.OpenFile(redeemPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
                        if err != nil { logging.Errorf("Open error: %s\n", err) }

                        t := time.Now()
			var tmpstr string
                        tmpstr = fmt.Sprintf("%d", t.Unix())
                        f.WriteString(tmpstr)
                        f.WriteString(";")
                        f.WriteString(cs_response.ID)
                        f.WriteString(";")
                        tmpstr = fmt.Sprintf("%d", cs_response.ExpectedAmount)
                        f.WriteString(tmpstr)
                        f.WriteString(";")
                        f.WriteString(cs_response.Address)
                        f.WriteString(";")
                        f.WriteString(s_invoice)
                        f.WriteString(";")
                        f.WriteString(cs_response.RedeemScript)
                        f.WriteString(";")
                        tmpstr = fmt.Sprintf("%d", cs_response.TimeoutBlockHeight)
                        f.WriteString(tmpstr)
                        f.WriteString(";")

                        err = f.Close();
                        if err != nil { logging.Errorf("Close error: %s\n", err) }

                        tmpstr = fmt.Sprintf("%d", cs_response.ExpectedAmount)
                        logging.Infof("Boltz response: %s %s\n", tmpstr, cs_response.Address)

                        return tmpstr, cs_response.Address, nil
                //else
        }
}

func (m *Backend) PrepareSweepSub(vtc_inv int64, addr string) string {
        logging.Debugf("Preparing submarine sweep")

        txs, err := m.wal.PrepareSweepSubWal(vtc_inv, addr)
        if err != nil {
                logging.Errorf("Error preparing sweep: %v", err)
                return err.Error()
        }

        m.pendingSweep = txs
        val := float64(0)
        for _, tx := range txs {
                val += (float64(tx.TxOut[1].Value) / float64(100000000))
        }

        result := PrepareResult{fmt.Sprintf("%0.8f VTC", val), len(txs)}
        logging.Debugf("Prepared submarine sweep: %v", result)

        return ""
}

func (m *Backend) SendSweepSub(password string) []string {

        txids := make([]string, 0)

        if len(m.pendingSweep) == 0 {
                // Somehow user managed to press send without properly
                // preparing the sweep first
                return []string{"send_failed"}
        }

        for _, s := range m.pendingSweep {
                err := m.wal.SignMyInputs(s, password)
                if err != nil {
                        logging.Errorf("Error signing transaction: %s", err.Error())
                        return []string{"sign_failed"}
                }

                txHash, txHex, err := m.wal.SendSub(s)
                if err != nil {
                        logging.Errorf("Error sending transaction: %s", err.Error())
                        return []string{"send_failed"}
                }
                txids = append(txids, txHash)

                lockupTransactionRaw, err := hex.DecodeString(txHex)
                if err != nil { logging.Errorf("Could not decode lockup transaction\n") }

                lockupTransaction, err := btcutil.NewTxFromBytes(lockupTransactionRaw)
                if err != nil { logging.Errorf("Could not parse lockup transaction\n") }

                outputs := make([]OutputDetails, 1)

                outputs[0].LockupTransaction = lockupTransaction
                outputs[0].Vout = 1
                outputs[0].OutputType = SegWit

                redeemPath := filepath.Join(util.DataDirectory(), "wifi/redeem.txt")

                if _, err := os.Stat(redeemPath); err == nil {
                        f2, err := os.Open(redeemPath)
                        if err != nil { logging.Errorf("Open error: %s", err) }

                        reader := bufio.NewReader(f2)
                        var line string
                        line, err = reader.ReadString('\n')
                        err = f2.Close();
                        if err != nil { logging.Errorf("Close error: %s", err) }

                        line_split := strings.Split(line, ";")

                        redeem_bytes, err := hex.DecodeString(line_split[5])
                        if err != nil { logging.Errorf("Could not convert redeem script\n") }

                        outputs[0].RedeemScript = redeem_bytes

                        privBytes, err := keyfile.LoadPrivateKey(password)
                        if err != nil { logging.Errorf("LoadPrivateKey failure\n") }
                        priv, pub := btcec.PrivKeyFromBytes(btcec.S256(), privBytes)

                        outputs[0].PrivateKey = priv
                        //outputs[0].Preimage = []byte{}

                        block_no, err := strconv.ParseUint(line_split[6], 10, 64)
                        if err != nil { logging.Errorf("Parse error: %s", err) }
                        outputs[0].TimeoutBlockHeight = uint32(block_no)

                        params := getVertcoinChainParams()
                        chaincfg.Register(&params)

                        pubHash := btcutil.Hash160(pub.SerializeCompressed())

                        witnessAddress, _ := btcutil.NewAddressWitnessPubKeyHash(pubHash, &params)
                        address, _ := btcutil.DecodeAddress(witnessAddress.EncodeAddress(), &params)

                        txref, err := ConstructTransaction(outputs, address, 500)
                        if err != nil { logging.Errorf("ConstructTransaction failure %s\n", err) }

                        var b bytes.Buffer
                        txref.Serialize(&b)
                        encref := hex.EncodeToString(b.Bytes())

                        f, err := os.OpenFile(redeemPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                        if err != nil { logging.Errorf("Open error: %s\n", err) }

                        f.WriteString(txHash)
                        f.WriteString(";")
                        f.WriteString(encref)

                        err = f.Close();
                        if err != nil { logging.Errorf("Close error: %s\n", err) }
                }
        }

        m.pendingSweep = nil

        logging.Debugf("Submarine transaction sent! TXIDs: %v\n", txids)
        m.refreshBalanceChan <- true
        return txids
}

func getVertcoinChainParams() chaincfg.Params {
    var params chaincfg.Params

    params.Bech32HRPSegwit = "vtc"

    return params
}

func ConstructTransaction(outputs []OutputDetails, outputAddress btcutil.Address, satPerVbyte int64) (*wire.MsgTx, error) {
        noFeeTransaction, err := constructTransaction(outputs, outputAddress, 0)

        if err != nil {
                return nil, err
        }

        witnessSize := noFeeTransaction.SerializeSize() - noFeeTransaction.SerializeSizeStripped()
        vByte := int64(noFeeTransaction.SerializeSizeStripped()) + int64(math.Ceil(float64(witnessSize)/4))

        return constructTransaction(outputs, outputAddress, vByte*satPerVbyte)
}

func constructTransaction(outputs []OutputDetails, outputAddress btcutil.Address, fee int64) (*wire.MsgTx, error) {
        transaction := wire.NewMsgTx(wire.TxVersion)

        var inputSum int64

        for _, output := range outputs {
                // Set the highest timeout block height as locktime
                if output.TimeoutBlockHeight > transaction.LockTime {
                        transaction.LockTime = output.TimeoutBlockHeight
                }

                // Calculate the sum of all inputs
                inputSum += output.LockupTransaction.MsgTx().TxOut[output.Vout].Value

                // Add the input to the transaction
                input := wire.NewTxIn(wire.NewOutPoint(output.LockupTransaction.Hash(), output.Vout), nil, nil)
                input.Sequence = 0

                transaction.AddTxIn(input)
        }

        // Add the output
        outputScript, err := txscript.PayToAddrScript(outputAddress)

        if err != nil {
                return nil, err
        }

        transaction.AddTxOut(&wire.TxOut{
                PkScript: outputScript,
                Value:    inputSum - fee,
        })

        // Construct the signature script and witnesses and sign the inputs
        for i, output := range outputs {
                switch output.OutputType {
                case Legacy:
                        // Set the signed signature script for legacy output
                        signature, err := txscript.RawTxInSignature(
                                transaction,
                                i,
                                output.RedeemScript,
                                txscript.SigHashAll,
                                output.PrivateKey,
                        )

                        if err != nil {
                                return nil, err
                        }

                        signatureScriptBuilder := txscript.NewScriptBuilder()
                        signatureScriptBuilder.AddData(signature)
                        signatureScriptBuilder.AddData(output.Preimage)
                        signatureScriptBuilder.AddData(output.RedeemScript)

                        signatureScript, err := signatureScriptBuilder.Script()

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].SignatureScript = signatureScript

                case Compatibility:
                        // Set the signature script for compatibility outputs
                        signatureScriptBuilder := txscript.NewScriptBuilder()
                        signatureScriptBuilder.AddData(createNestedP2shScript(output.RedeemScript))

                        signatureScript, err := signatureScriptBuilder.Script()

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].SignatureScript = signatureScript
                }

                // Add the signed witness in case the output is not a legacy one
                if output.OutputType != Legacy {
                        signatureHash := txscript.NewTxSigHashes(transaction)
                        signature, err := txscript.RawTxInWitnessSignature(
                                transaction,
                                signatureHash,
                                i,
                                output.LockupTransaction.MsgTx().TxOut[output.Vout].Value,
                                output.RedeemScript,
                                txscript.SigHashAll,
                                output.PrivateKey,
                        )

                        if err != nil {
                                return nil, err
                        }

                        transaction.TxIn[i].Witness = wire.TxWitness{signature, output.Preimage, output.RedeemScript}
                }
        }

        return transaction, nil
}

func createNestedP2shScript(redeemScript []byte) []byte {
        addressScript := []byte{
                txscript.OP_0,
                txscript.OP_DATA_32,
        }

        redeemScriptHash := sha256.Sum256(redeemScript)
        addressScript = append(addressScript, redeemScriptHash[:]...)

        return addressScript
}

