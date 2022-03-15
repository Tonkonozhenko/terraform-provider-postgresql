package postgresql

import (
	"database/sql"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
	"log"
	"strings"
)

const (
	policyNameAttr                 = "name"
	policySchemaAttr               = "schema"
	policyTableAttr                = "table"
	policyToAttr                   = "to"
	policyUsingAttr                = "using"
	policyPropagateToInheritedAttr = "propagate_to_inherited"
)

func resourcePostgreSQLPolicy() *schema.Resource {
	return &schema.Resource{
		Create: PGResourceFunc(resourcePostgreSQLPolicyCreate),
		Read:   PGResourceFunc(resourcePostgreSQLPolicyRead),
		Update: PGResourceFunc(resourcePostgreSQLPolicyUpdate),
		Delete: PGResourceFunc(resourcePostgreSQLPolicyDelete),
		Exists: PGResourceExistsFunc(resourcePostgreSQLPolicyExists),

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			policyNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Sets policy name",
			},
			policySchemaAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Sets the target schema for policy",
			},
			policyTableAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Sets the target table for policy",
			},
			policyToAttr: {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Sets the role for policy to be used by",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			policyUsingAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Sets the RLS filter",
			},
			policyPropagateToInheritedAttr: {
				Type:        schema.TypeBool,
				ForceNew:    true,
				Optional:    true,
				Default:     false,
				Description: "Enable policy propagation to inherited tables",
			},
		},
	}
}

func resourcePostgreSQLPolicyCreate(db *DBConnection, d *schema.ResourceData) error {
	policyName := d.Get(policyNameAttr).(string)
	policyToRaw := d.Get(policyToAttr).([]interface{})
	policyUsing := d.Get(policyUsingAttr).(string)

	policyTo := make([]string, len(policyToRaw))
	for i := range policyToRaw {
		policyTo[i] = policyToRaw[i].(string)
	}

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		split := strings.Split(partition, ".")
		partitionSchema, partitionTable := split[0], split[1]

		q1 := fmt.Sprintf(`DO $$ BEGIN
		   IF NOT EXISTS (
			  SELECT *
				FROM pg_tables
				WHERE schemaname = '%[1]s'
				  AND tablename = '%[2]s'
				  AND rowsecurity) THEN
			  ALTER TABLE %[1]s.%[2]s ENABLE ROW LEVEL SECURITY;
		   END IF;
		END $$;`, partitionSchema, partitionTable)

		if _, err := txn.Exec(q1); err != nil {
			return err
		}

		q2 := fmt.Sprintf(
			`DO $$ BEGIN
			   IF NOT EXISTS (
				  SELECT *
					FROM pg_policies
					WHERE schemaname = '%[1]s'
					  AND tablename = '%[2]s'
					  AND policyname = '%[3]s') THEN
				  CREATE POLICY %[3]s ON %[1]s.%[2]s TO %[4]s
					  USING (%[5]s);
			   END IF;
			END $$`,
			partitionSchema,
			partitionTable,
			policyName,
			strings.Join(policyTo, ", "), // TODO: quote policyTo
			policyUsing,
		)
		//panic(q2)

		if _, err := txn.Exec(q2); err != nil {
			return err
		}
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error creating Policy: %w", err)
	}

	d.SetId(generatePolicyID(d))

	return resourcePostgreSQLPolicyRead(db, d)
}

func resourcePostgreSQLPolicyRead(db *DBConnection, d *schema.ResourceData) error {
	var policySchema string
	var policyTable string
	var policyName string
	var policyTo []string
	var policyUsing string

	policySchema, policyTable, policyName = getInfoFromID(d.Id())

	err := db.QueryRow(
		"SELECT roles :: varchar[], qual FROM pg_policies WHERE schemaname = $1 AND tablename = $2 AND policyname = $3",
		policySchema, policyTable, policyName,
	).Scan(pq.Array(&policyTo), &policyUsing)
	switch {
	case err == sql.ErrNoRows:
		log.Printf("[WARN] PostgreSQL policy (%q ON (%q.%q) not found", policyName, policySchema, policyTable)
		d.SetId("")
		return nil
	case err != nil:
		return fmt.Errorf("Error reading policy: %w", err)
	}

	d.Set(policyNameAttr, policyName)
	d.Set(policySchemaAttr, policySchema)
	d.Set(policyTableAttr, policyTable)
	d.Set(policyToAttr, policyTo)
	//d.Set(policyUsingAttr, policyUsing[1:len(policyUsing)-1])

	return nil
}

func resourcePostgreSQLPolicyUpdate(db *DBConnection, d *schema.ResourceData) error {
	policyName := d.Get(policyNameAttr).(string)
	policyToRaw := d.Get(policyToAttr).([]interface{})
	policyUsing := d.Get(policyUsingAttr).(string)

	policyTo := make([]string, len(policyToRaw))
	for i := range policyToRaw {
		policyTo[i] = policyToRaw[i].(string)
	}

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		if d.HasChange(policyNameAttr) {
			policyNameOld, _ := d.GetChange(policyNameAttr)

			q := fmt.Sprintf(
				"ALTER POLICY %s ON %s RENAME TO %s",
				pq.QuoteIdentifier(policyNameOld.(string)),
				partition,
				pq.QuoteIdentifier(policyName),
			)
			if _, err := txn.Exec(q); err != nil {
				return err
			}
		}

		if d.HasChangeExcept(policyNameAttr) {
			q := fmt.Sprintf(
				"ALTER POLICY %s ON %s TO %s USING (%s)",
				pq.QuoteIdentifier(policyName),
				partition,
				strings.Join(policyTo, ", "), // TODO: quote policyTo
				policyUsing,
			)
			if _, err := txn.Exec(q); err != nil {
				return err
			}
		}
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error updating Policy: %w", err)
	}

	d.SetId(generatePolicyID(d))

	return resourcePostgreSQLPolicyRead(db, d)
}

func resourcePostgreSQLPolicyDelete(db *DBConnection, d *schema.ResourceData) error {
	policyName := d.Get(policyNameAttr).(string)

	txn, err := startTransaction(db.client, db.client.databaseName)
	if err != nil {
		return err
	}
	defer deferredRollback(txn)

	tablePartitions, err := tablePartitions(db, d)
	if err != nil {
		return err
	}

	for _, partition := range tablePartitions {
		q := fmt.Sprintf(
			"DROP POLICY IF EXISTS %s ON %s",
			pq.QuoteIdentifier(policyName),
			partition,
		)

		if _, err := txn.Exec(q); err != nil {
			return err
		}
	}

	if err = txn.Commit(); err != nil {
		return fmt.Errorf("error deleting Policy: %w", err)
	}

	d.SetId("")

	return nil
}

func resourcePostgreSQLPolicyExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	var policySchema string
	var policyTable string
	var policyName string
	policySchema, policyTable, policyName = getInfoFromID(d.Id())

	err := db.QueryRow(
		"SELECT policyname FROM pg_policies WHERE policyname = $1 AND schemaname = $2 AND tablename = $3",
		policyName, policySchema, policyTable,
	).Scan(&policyName)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func generatePolicyID(d *schema.ResourceData) string {
	return strings.Join([]string{
		d.Get(policySchemaAttr).(string),
		d.Get(policyTableAttr).(string),
		d.Get(policyNameAttr).(string),
	}, ".")
}

func getInfoFromID(ID string) (string, string, string) {
	splitted := strings.Split(ID, ".")
	return splitted[0], splitted[1], splitted[2]
}
