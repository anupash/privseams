/* xmlparser.c reads/writes the xml messages */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <libxml2/libxml/tree.h>
#include "libhipopendhtxml.h"
#include "debug.h"

xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value);

/** 
 * build_packet_put - Builds HTTP XML packet for put
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param value Value to be stored in to the openDHT 
 * @param value_len Lenght of value in bytes
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_put(unsigned char * key, 
                     int key_len,
		     unsigned char * value,
                     int value_len, 
                     int port,
                     unsigned char * host_ip,
		     char * out_buffer) 
{
    char *key64 = NULL;
    char *value64 = NULL;
    key64 = (char *)base64_encode((unsigned char *)key, (unsigned int)key_len);
    value64 = (char *)base64_encode((unsigned char *)value, (unsigned int)value_len);

    /* Create a XML document */
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_root = NULL;
    xmlNodePtr xml_node;
    unsigned char *xml_buffer = NULL;
    int xml_len = 0;

    xml_doc = xmlNewDoc(BAD_CAST "1.0");
    xml_root = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(xml_doc, xml_root);
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "put");
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "params", NULL);
    xml_new_param(xml_node, "base64", (char *)key64);
    xml_new_param(xml_node, "base64", (char *)value64);
    xml_new_param(xml_node, "int", TTL);  
    xml_new_param(xml_node, "string", BAD_CAST "HIPL");
    xmlDocDumpFormatMemory(xml_doc, &xml_buffer, &xml_len, 0);

    memset(out_buffer, '\0', sizeof(out_buffer));
    sprintf(out_buffer, 
            "POST /RPC2 HTTP/1.0\r\nUser-Agent: "
            "hipl\r\nHost: %s:%d\r\nContent-Type: "
            "text/xml\r\nContent-length: %d\r\n\r\n", 
            host_ip, port, xml_len); 
    memcpy(&out_buffer[strlen(out_buffer)], xml_buffer, xml_len);
  
    xmlFree(xml_buffer);
    xmlFreeDoc(xml_doc);
    free(key64);
    free(value64); 
    return(0);
}

/** 
 * build_packet_get - Builds HTTP XML packet for get
 * @param key Key that is used in to the openDHT
 * @param key_len Length of the key in bytes
 * @param port Port for the openDHT (5851)
 * @param host_ip Host IP
 * @param out_buffer Completed packet will be in this buffer
 *
 * @return integer 0
 */
int build_packet_get(unsigned char * key,
                     int key_len,
                     int port,
                     unsigned char * host_ip,
		     char * out_buffer) 
{
    char *key64 = NULL; 
    key64 = (char *)base64_encode((unsigned char *)key, (unsigned int)key_len);

    /* Create a XML document */
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_root = NULL;
    xmlNodePtr xml_node;
    unsigned char *xml_buffer = NULL;
    int xml_len = 0;

    xml_doc = xmlNewDoc(BAD_CAST "1.0");
    xml_root = xmlNewNode(NULL, BAD_CAST "methodCall");
    xmlDocSetRootElement(xml_doc, xml_root);
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "methodName", BAD_CAST "get");
    xml_node = xmlNewChild(xml_root, NULL, BAD_CAST "params", NULL);
    xml_new_param(xml_node, "base64", (char *)key64);
    xml_new_param(xml_node, "int", "10");	/* maxvals */
    xml_new_param(xml_node, "base64", "");	/* placemark */ 
    xml_new_param(xml_node, "string", BAD_CAST "HIPL");
    xmlDocDumpFormatMemory(xml_doc, &xml_buffer, &xml_len, 0);

    memset(out_buffer, '\0', sizeof(out_buffer));
    sprintf(out_buffer, 
            "POST /RPC2 HTTP/1.0\r\nUser-Agent: "
            "hipl\r\nHost: %s:%d\r\nContent-Type: "
            "text/xml\r\nContent-length: %d\r\n\r\n", 
            host_ip, port, xml_len); 
    memcpy(&out_buffer[strlen(out_buffer)], xml_buffer, xml_len);
  
    xmlFree(xml_buffer);
    xmlFreeDoc(xml_doc);  
    free(key64);
    return(0);
}

/** 
 * read_packet_content - Builds HTTP XML packet for put
 * @param in_buffer Should contain packet to be parsed including the HTTP header
 * @param out_value Value received is stored here
 *
 * @return Integer -1 if error, on success 0
 */
int read_packet_content(char * in_buffer, char * out_value)
{
    int ret = 0;
    int evpret = 0;
    char * place = NULL;
    char tmp_buffer[2048]; 
    xmlDocPtr xml_doc = NULL;
    xmlNodePtr xml_node;
    xmlNodePtr xml_node_value;
    xmlChar *xml_data;
    memset(tmp_buffer, '\0', sizeof(tmp_buffer));
    memset(out_value, '\0', sizeof(out_value));

    /*!!!! is there a http header !!!!*/
    if (strncmp(in_buffer, "HTTP", 4) !=0) 
    { 
        HIP_DEBUG("Parser error: no HTTP header in the packet.\n");
        ret = -1;
        goto out_err;
    }
    
    /* is there a xml document */
    if ((place = strstr(in_buffer, "<?xml")) == NULL)
    {
        HIP_DEBUG("Parser error: no XML content in the packet.\n");
        ret = -1;
        goto out_err;
    }

    /* copy the xml part to tmp_buffer */
    sprintf(tmp_buffer, "%s\n", place);

    if ((xml_doc = xmlParseMemory(tmp_buffer, strlen(tmp_buffer))) == NULL)    
    { 
        HIP_DEBUG("Libxml2 encountered error while parsing content.\n");
        ret = -1;
        goto out_err;
    }

    xml_node = xmlDocGetRootElement(xml_doc);
    if (xml_node->children) /* params or fault */
    {
        xml_node = xml_node->children;
        /* check if error from DHT 
           <fault><value><struct><member><name>faultString</name><value>java...
        */
        if (!strcmp((char *)xml_node->name, "fault"))
        {
             if (xml_node->children)
                  xml_node = xml_node->children; /* value */
             if (xml_node->children) 
                  xml_node = xml_node->children; /* struct */
             if (xml_node->children)
                  xml_node = xml_node->children; /* member */
             if (xml_node->children)
                  xml_node = xml_node->children; /* name */
             if (xml_node->next)
             {
                  xml_node_value = xml_node->next; /* value */
                  xml_data = xmlNodeGetContent(xml_node_value);
                  /* strcpy((char *)out_value, (char *)xml_data); */
                  xmlFree(xml_data);
                  HIP_DEBUG("Error from the openDHT: %s\n", xml_data);
                  ret = -1;
                  goto out_err;
             }
        }
    }

    if (xml_node->children) /* param */
        xml_node = xml_node->children;
    if (!xml_node)
    {
        HIP_DEBUG("Parser error: unknown XML format.\n");
        ret = -1;
        goto out_err;
    }
    xml_node_value = NULL;
    if (!strcmp((char *)xml_node->name, "param") &&
        xml_node->children &&
        !strcmp((char *)xml_node->children->name, "value"))
        xml_node_value = xml_node->children->children;
    if(!xml_node_value)
    {
        HIP_DEBUG("Parser error: element has no content.\n");
        ret = -1;
        goto out_err;
    }    

    /* If there is a string "<int>" in the response, then there is only status code */
    place = NULL;
    if ((place = strstr(tmp_buffer, "<int>")) != NULL)
    {
        /* retrieve status code only */
        xml_data = xmlNodeGetContent(xml_node_value);
        if (strcmp((char *)xml_node_value->name, "int")==0)
        {
            sscanf((const char *)xml_data, "%d", &ret);
            xmlFree(xml_data);
           // xmlFreeDoc(xml_doc);
            if (ret == 0) /* put success */
                goto out_err;
            if (ret == 1);
            {
                HIP_DEBUG("OpenDHT error: over capacity.\n");
                ret = -1;
                goto out_err;
            }
            if (ret == 2)
            {
                HIP_DEBUG("OpenDHT error: try again.\n");
                ret = -1;
                goto out_err;
            }
        }
        else
        {
            HIP_DEBUG("Parser error: did not find status code.\n");
            ret = -1;
            goto out_err;
        }
    }
    else
    {
        /* retrieve the first value in array */
        if (!strcmp((char *)xml_node_value->name, "array") &&
            xml_node_value->children &&
            !strcmp((char *)xml_node_value->children->name, "data"))
            xml_node = xml_node_value->children->children;
                      
        if (!strcmp((char *)xml_node->name, "value") &&
            xml_node->children &&
            !strcmp((char *)xml_node->children->name, "array"))
            xml_node = xml_node->children->children; /* inner data element */
              
         if (!strcmp((char *)xml_node->children->children->name, "base64"))
         {         
             xml_node_value = xml_node->children->children; /* should be base64 */
             xml_data = xmlNodeGetContent(xml_node_value);
             evpret = EVP_DecodeBlock((unsigned char *)out_value, xml_data, 
                                      strlen((char *)xml_data));
             out_value[evpret] = '\0';
             xmlFree(xml_data);
             ret = 0;
             goto out_err;
         }
         HIP_DEBUG("Parser error: couldn't parse response value.\n");
         ret = -1;
         goto out_err;
    }
    /* should be impossible to get here */
    HIP_DEBUG("Parser error: unknown error.\n");
    ret = -1; 

 out_err:
    if (xml_doc != NULL) 
        xmlFreeDoc(xml_doc);
    return(ret);
}

/* build_packet_get and build_packet_put helper function*/
xmlNodePtr xml_new_param(xmlNodePtr node_parent, char *type, char *value)
{
    xmlNodePtr xml_node_param;
    xmlNodePtr xml_node_value;
    xml_node_param = xmlNewChild(node_parent, NULL, BAD_CAST "param", NULL);
    xml_node_value = xmlNewChild(xml_node_param, NULL, BAD_CAST "value", NULL);
    return(xmlNewChild(xml_node_value, NULL, BAD_CAST type, BAD_CAST value)); 
}

/** 
 * base64_encode - Encodes given content to Base64
 * @param buf Pointer to contents to be encoded
 * @param len How long is the first parameter in bytes
 *
 * @return Returns a pointer to encoded content
 */
unsigned char * base64_encode(unsigned char * buf, unsigned int len)
{
    unsigned char * ret;
    unsigned int b64_len;

    b64_len = (((len + 2) / 3) * 4) + 1;
    ret = (unsigned char *)malloc(b64_len);
    EVP_EncodeBlock(ret, buf, len);
    return ret;
}

/** 
 * base64_decode - Dencodes given base64 content
 * @param buf Pointer to contents to be decoded
 * @param len How long is the first parameter in bytes
 *
 * @return Returns a pointer to decoded content
 */
unsigned char * base64_decode(unsigned char * bbuf, unsigned int *len)
{
    unsigned char * ret;
    unsigned int bin_len;
  
    bin_len = (((strlen((char *)bbuf) + 3) / 4) * 3);
    ret = (unsigned char *)malloc(bin_len);
    *len = EVP_DecodeBlock(ret, bbuf, strlen((char *)bbuf));
    return ret;
}
