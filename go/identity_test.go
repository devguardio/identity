package identity


import (
    "testing"
    "fmt"
)

func TestIdentityFromStringGarbage(t *testing.T) {
    _ , err :=  IdentityFromString("cDFIOBGBIVQAW2YVIWVLMV19203819028390182390128312312313QA");
    if err == nil {
        t.Errorf("parsing must not succeed");
    }
}

var secret_string   string = "cCOMZM5Z2HHCSVE65EDABQYXZHFA4AFH7NCTFG2VJ6V5OX7OXI33PMUQ";
var identity_string string = "cDFXSA73D3H4MOM7HPVUYWUOABQI7D5ERUR7QXOQPJD2HOYYSJCIYFWY";
var sequence_string string = "+P5DQ";
var sequence_value Serial = 18303
var sequence2_string string = "+AI";
var sequence2_string2 string = "+ai";
var sequence2_value Serial = 2
var message_string string = "cDYCWQZLMNRXXO33SNRSNG"

func TestSecret(t *testing.T) {
    sk, err := SecretFromString(secret_string);
    if err != nil {
        panic(err);
    }

    if sk.String() == secret_string {
        t.Errorf("leaking secrets");
    }

    if sk.ToString() != secret_string {
        t.Errorf("expected SecretFromString(s).AsString() == s")
    }
}

func TestEd25519(t *testing.T) {
    sk, err := SecretFromString(secret_string);
    if err != nil {
        panic(err);
    }

    id, err := sk.Identity();
    if err != nil {
        panic(err);
    }

    if id.String() != identity_string {
        t.Errorf("expected SecretFromString(s).Identity().String() == identity_string")
    }
}

func TestIdentity(t *testing.T) {
    sk, err := IdentityFromString(identity_string);
    if err != nil {
        panic(err);
    }

    if sk.String() != identity_string {
        t.Errorf("expected IdentityFromString(s).AsString() == s")
    }
}

func TestSerial(t *testing.T) {
    sk, err := SerialFromString(sequence_string);
    if err != nil {
        panic(err);
    }

    if sk != sequence_value {
        t.Errorf("expected SerialFromString(s) == sv")
    }

    if sk.String() != sequence_string {
        t.Errorf("expected SerialFromString(s).String() == s")
    }
}

func TestSerial2(t *testing.T) {
    sk, err := SerialFromString(sequence2_string);
    if err != nil {
        panic(err);
    }

    if sk != sequence2_value {
        t.Errorf(fmt.Sprintf("expected SerialFromString(s) == sv | %v != %v", sk, sequence2_value))
    }

    if sk.String() != sequence2_string {
        t.Errorf("expected SerialFromString(s).String() == s")
    }
}

func TestSerial2b(t *testing.T) {
    sk, err := SerialFromString(sequence2_string2);
    if err != nil {
        panic(err);
    }

    if sk != sequence2_value {
        t.Errorf(fmt.Sprintf("expected SerialFromString(s) == sv | %v != %v", sk, sequence2_value))
    }

    if sk.String() != sequence2_string {
        t.Errorf("expected SerialFromString(s).String() == s")
    }
}


func TestMessage(t *testing.T) {
    sk, err := MessageFromString(message_string);
    if err != nil {
        panic(err);
    }

    if sk.String() != message_string{
        t.Errorf("expected MessageFromString(s).String() == s")
    }
}


func TestCompare(t *testing.T) {

    id1, err := IdentityFromString(identity_string);
    if err != nil { panic(err); }

    id2, err := IdentityFromString(identity_string);
    if err != nil { panic(err); }

    sk, err := CreateSecret()
    if err != nil { panic(err); }

    id3, err := sk.Identity()
    if err != nil { panic(err); }

    if !id1.Equal(id1){
        t.Errorf("not equal self");
    }

    if !id1.Equal(id2){
        t.Errorf("not equal same fromstring");
    }

    if id2.Equal(id3){
        t.Errorf("should not be equal random");
    }
}
