/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include "latency.h"

#include <sys/mman.h>


/*
 * This random string identifies an OpenVPN latency measure packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 */
 const uint8_t send_data[] = {
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb
  };


float get_latency_host(struct connection_entry * host, int * mem, int index)
{

  struct addrinfo hints, *res, *res0;

  unsigned long port;
  char * dummy;
  const char *cause = NULL;

  int s, error, pck, timeout, recv_data_len, i;

  float ping, ping_avg;

  struct timeval tv_tmp;
  struct timeval timestamp_send;
  struct timeval timestamp_return;
  struct timeval tv;
	
  char port_char[10];
  sprintf(port_char,"%d",host->remote_port);
  port = strtoul(port_char, &dummy, 10);
  if(port < 1 || port > 65535 || *dummy != '\0')
  {
    fprintf(stderr, "Invalid port number: %d\n", host->remote_port);
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  error = getaddrinfo(host->remote,port_char,&hints,&res0);
  if(error)
  {
    perror(gai_strerror(error));
    return (-1);
  }

  s= -1;
  for (res = res0; res; res = res->ai_next)
  {
    s = socket(res->ai_family, res->ai_socktype, 0);
    break;
  }

  timeout = 2000;
  tv.tv_sec = timeout/1000;
  tv.tv_usec = 0;
  if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0)
  {
    perror("Error");
  }

  pck = 5;
  ping_avg = 0.0f;

  for(i=0; i<pck; i++)
  {
    ping=0.0f; recv_data_len = 0;
	
    sendto(s, (void *)send_data,sizeof(send_data), 0,res->ai_addr,res->ai_addrlen);
    gettimeofday(&timestamp_send,NULL);

    recv_data_len = recvfrom(s,(void *)send_data,sizeof(send_data),0,res->ai_addr,&res->ai_addrlen);
    gettimeofday(&timestamp_return,NULL);

    timersub(&timestamp_return, &timestamp_send, &tv_tmp);
    ping = ((float)tv_tmp.tv_sec)*1000+((float)tv_tmp.tv_usec)/1000;


    if(ping<timeout)
    {
            ping_avg = ping_avg+ping;
        } 
        else 
        {
            ping = 2000;
        }
  }

  ping_avg = ping_avg/pck;
  mem[index] = (int) ping_avg;

  return 0;

}





void rank_host_by_latency(struct connection_list * l)
{
  int size = l->len;
  int tab_sorted[size];
  int tab_unsorted[size];
  struct connection_list * temp;
  int i,x,y;

  pid_t pids[size];
  int n = size;

  int shm_fd;
  int* shared_memory;
  int msize; // the size (in bytes) of the shared memory segment 
  const char *name = "/LATENCY";

  int status;
  pid_t pid;

  memcpy(&temp,&l,sizeof(temp));

  // calculating the array size based on the number of terms being passed from child to parent
  msize = (n)*sizeof(int); 

  // open the memory
  shm_fd = shm_open(name, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG);
  printf("SHM %d\n", shm_fd);
  if (shm_fd < 0) 
  {
    printf("Error in shm_open(): %s\n",strerror(errno));
  }

  // attach the shared memory segment
  ftruncate(shm_fd, msize);

  // allocating the shared memory
  shared_memory = (int *) mmap(NULL, msize, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  if (shared_memory == NULL) 
  {
	fprintf(stderr,"Error in mmap()");
  }

  for (i = 0; i < n; ++i) 
  {
    if ((pids[i] = fork()) < 0) 
	{
	  perror("fork");
	  abort();
    } 
	else if (pids[i] == 0) 
	{
	  get_latency_host(l->array[i], shared_memory, i); 
	  exit(0);
    }
  }


  while (n > 0) 
  {
    pid = wait(&status);
    --n;  
  }

  shm_unlink(name);
  for(i=0; i<size; i++)
  {
    tab_sorted[i]=shared_memory[i];
    tab_unsorted[i]=shared_memory[i];
  }


  for(x=0; x<size; x++)
  {
    int index_of_min = x;
    for(y=x; y<size; y++)
    {
      if(tab_sorted[index_of_min]>tab_sorted[y])
      {
        index_of_min = y;
      }
    }
	float temp = tab_sorted[x];
	tab_sorted[x] = tab_sorted[index_of_min];
	tab_sorted[index_of_min] = temp;
  }

  for(x=0; x < size; x++)
  {
    for(y=0; y < size; y++)
    {
      if(tab_sorted[x]==tab_unsorted[y])
      {
        memcpy(&temp->array[x],&l->array[y],sizeof(temp->array[x]));
      }
    }
  }

  for(i = 0; i < size; i++)
  {
    memcpy(&l->array[i],&temp->array[i],sizeof(l->array[i]));
  }
}

