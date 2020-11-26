# Insecure Direct Object References (IDOR)

## Description

An Insecure Direct Object Reference (IDOR) occurs when the application exposes, in an unintended way, references to internal implementations such as primary keys, file identifiers, directory names, databases. In these circumstances, a malicious user could manipulate such parameters to gain unauthorized access.

For example, an API endpoint that exposes a bank account number in the URI and it is supposed to return all the account activity for that account. 
If the account identifier corresponds to a predictable value (either a numeric sequence or a easy-to-guest composition), the malicious user (who can be a legitimate user of the application), can arbitrarily change that value.

See below code examples.

## Code Examples

```node
app.get('/account-history/:account_id', function(req, res) {
    //extracting the bank account
    var bank_account = req.params.account_id;

    db.fetch_account_history( account_id, function(req, res){
        //do some other logic here
    })
});
```

In this case, the application does not perform any authorization checks to return the account's history just to  users with any type of relationship within the given account number (owner, authorized, joint account)

## Mitigation

If internal identifiers need to be exposed for any circumstance, it's required to perform exhaustive authentication and authorization checks and reject any suspicious request.


```node
app.get('/account-history/:account_id', function(req, res) {
    //extracting the bank account
    var bank_account = req.params.account_id;
    var username     = req.session.username;

    db.fetch_account_history(username, account_id, function(req, res){
        //do some other logic here
        //SELECT date,transacction_id, description, amount
        //FROM bank_accounts WHERE account_id = account_id
        //AND account_owner = username
    })
});
```
Additional recommendations to mitigate this issue are:
* Always check access: Verify that the user is authorized to access the requested object.
* Use a surrogate identifier to reference internal resources. An intermediary mapping table can translate the requested object identifier with the internal value.
* Perform security testing to identify these flaws in the source code.

# Risk Assessment

Insecure Direct Object References presents a moderate impact on organizations. However, the impact of exploiting this vulnerability in an automated fashion (via brute-forcing attacks) could have a high impact because a large dataset of transactions could be easily leaked and exfiltrated by a malicious user.

  

# References

[Insecure Direct Object References Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)

[Insecure Direct Object Reference IDOR](https://owasp.org/www-chapter-ghana/assets/slides/IDOR.pdf)
