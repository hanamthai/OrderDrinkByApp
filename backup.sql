PGDMP     "                    {            Drink Order    14.7    14.7 H    M           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            N           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            O           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            P           1262    16394    Drink Order    DATABASE     q   CREATE DATABASE "Drink Order" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United States.1252';
    DROP DATABASE "Drink Order";
                postgres    false            �            1259    16673 
   categories    TABLE     d   CREATE TABLE public.categories (
    categoryid integer NOT NULL,
    categoryname text NOT NULL
);
    DROP TABLE public.categories;
       public         heap    postgres    false            �            1259    16672    categories_categoryid_seq    SEQUENCE     �   CREATE SEQUENCE public.categories_categoryid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.categories_categoryid_seq;
       public          postgres    false    229            Q           0    0    categories_categoryid_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.categories_categoryid_seq OWNED BY public.categories.categoryid;
          public          postgres    false    228            �            1259    16554    drinks    TABLE     �   CREATE TABLE public.drinks (
    drinkid integer NOT NULL,
    drinkname text NOT NULL,
    drinkimage text,
    description text,
    status text NOT NULL,
    categoryid integer NOT NULL
);
    DROP TABLE public.drinks;
       public         heap    postgres    false            �            1259    16553    drinks_drinkid_seq    SEQUENCE     �   CREATE SEQUENCE public.drinks_drinkid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.drinks_drinkid_seq;
       public          postgres    false    220            R           0    0    drinks_drinkid_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.drinks_drinkid_seq OWNED BY public.drinks.drinkid;
          public          postgres    false    219            �            1259    16590    drinktopping    TABLE     c   CREATE TABLE public.drinktopping (
    drinkid integer NOT NULL,
    toppingid integer NOT NULL
);
     DROP TABLE public.drinktopping;
       public         heap    postgres    false            �            1259    16580 	   itemorder    TABLE     ]   CREATE TABLE public.itemorder (
    orderid integer NOT NULL,
    itemid integer NOT NULL
);
    DROP TABLE public.itemorder;
       public         heap    postgres    false            �            1259    16547    items    TABLE     �   CREATE TABLE public.items (
    itemid integer NOT NULL,
    drinkid integer NOT NULL,
    price numeric NOT NULL,
    itemquantity integer NOT NULL,
    sizeid integer NOT NULL
);
    DROP TABLE public.items;
       public         heap    postgres    false            �            1259    16546    items_itemid_seq    SEQUENCE     �   CREATE SEQUENCE public.items_itemid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.items_itemid_seq;
       public          postgres    false    218            S           0    0    items_itemid_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.items_itemid_seq OWNED BY public.items.itemid;
          public          postgres    false    217            �            1259    16585    itemtopping    TABLE     a   CREATE TABLE public.itemtopping (
    itemid integer NOT NULL,
    toppingid integer NOT NULL
);
    DROP TABLE public.itemtopping;
       public         heap    postgres    false            �            1259    16533    orders    TABLE     	  CREATE TABLE public.orders (
    orderid integer NOT NULL,
    userid integer NOT NULL,
    totalprice numeric NOT NULL,
    address text NOT NULL,
    phonenumber text NOT NULL,
    note text,
    status text NOT NULL,
    orderdate timestamp without time zone
);
    DROP TABLE public.orders;
       public         heap    postgres    false            �            1259    16532    orders_orderid_seq    SEQUENCE     �   CREATE SEQUENCE public.orders_orderid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.orders_orderid_seq;
       public          postgres    false    216            T           0    0    orders_orderid_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.orders_orderid_seq OWNED BY public.orders.orderid;
          public          postgres    false    215            �            1259    16572    sizes    TABLE     �   CREATE TABLE public.sizes (
    sizeid integer NOT NULL,
    namesize text NOT NULL,
    price numeric NOT NULL,
    drinkid integer
);
    DROP TABLE public.sizes;
       public         heap    postgres    false            �            1259    16571    sizes_sizeid_seq    SEQUENCE     �   CREATE SEQUENCE public.sizes_sizeid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.sizes_sizeid_seq;
       public          postgres    false    224            U           0    0    sizes_sizeid_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.sizes_sizeid_seq OWNED BY public.sizes.sizeid;
          public          postgres    false    223            �            1259    16563    toppings    TABLE     |   CREATE TABLE public.toppings (
    toppingid integer NOT NULL,
    nametopping text NOT NULL,
    price numeric NOT NULL
);
    DROP TABLE public.toppings;
       public         heap    postgres    false            �            1259    16562    toppings_toppingid_seq    SEQUENCE     �   CREATE SEQUENCE public.toppings_toppingid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.toppings_toppingid_seq;
       public          postgres    false    222            V           0    0    toppings_toppingid_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.toppings_toppingid_seq OWNED BY public.toppings.toppingid;
          public          postgres    false    221            �            1259    16524    users    TABLE     �   CREATE TABLE public.users (
    userid integer NOT NULL,
    phonenumber text NOT NULL,
    password text NOT NULL,
    fullname text NOT NULL,
    rolename text NOT NULL,
    address text NOT NULL,
    email text NOT NULL,
    status text NOT NULL
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16523    users_userid_seq    SEQUENCE     �   CREATE SEQUENCE public.users_userid_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.users_userid_seq;
       public          postgres    false    214            W           0    0    users_userid_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.users_userid_seq OWNED BY public.users.userid;
          public          postgres    false    213            �           2604    16676    categories categoryid    DEFAULT     ~   ALTER TABLE ONLY public.categories ALTER COLUMN categoryid SET DEFAULT nextval('public.categories_categoryid_seq'::regclass);
 D   ALTER TABLE public.categories ALTER COLUMN categoryid DROP DEFAULT;
       public          postgres    false    228    229    229            �           2604    16557    drinks drinkid    DEFAULT     p   ALTER TABLE ONLY public.drinks ALTER COLUMN drinkid SET DEFAULT nextval('public.drinks_drinkid_seq'::regclass);
 =   ALTER TABLE public.drinks ALTER COLUMN drinkid DROP DEFAULT;
       public          postgres    false    220    219    220            �           2604    16550    items itemid    DEFAULT     l   ALTER TABLE ONLY public.items ALTER COLUMN itemid SET DEFAULT nextval('public.items_itemid_seq'::regclass);
 ;   ALTER TABLE public.items ALTER COLUMN itemid DROP DEFAULT;
       public          postgres    false    217    218    218            �           2604    16536    orders orderid    DEFAULT     p   ALTER TABLE ONLY public.orders ALTER COLUMN orderid SET DEFAULT nextval('public.orders_orderid_seq'::regclass);
 =   ALTER TABLE public.orders ALTER COLUMN orderid DROP DEFAULT;
       public          postgres    false    215    216    216            �           2604    16575    sizes sizeid    DEFAULT     l   ALTER TABLE ONLY public.sizes ALTER COLUMN sizeid SET DEFAULT nextval('public.sizes_sizeid_seq'::regclass);
 ;   ALTER TABLE public.sizes ALTER COLUMN sizeid DROP DEFAULT;
       public          postgres    false    223    224    224            �           2604    16566    toppings toppingid    DEFAULT     x   ALTER TABLE ONLY public.toppings ALTER COLUMN toppingid SET DEFAULT nextval('public.toppings_toppingid_seq'::regclass);
 A   ALTER TABLE public.toppings ALTER COLUMN toppingid DROP DEFAULT;
       public          postgres    false    221    222    222            �           2604    16527    users userid    DEFAULT     l   ALTER TABLE ONLY public.users ALTER COLUMN userid SET DEFAULT nextval('public.users_userid_seq'::regclass);
 ;   ALTER TABLE public.users ALTER COLUMN userid DROP DEFAULT;
       public          postgres    false    213    214    214            J          0    16673 
   categories 
   TABLE DATA           >   COPY public.categories (categoryid, categoryname) FROM stdin;
    public          postgres    false    229   [R       A          0    16554    drinks 
   TABLE DATA           a   COPY public.drinks (drinkid, drinkname, drinkimage, description, status, categoryid) FROM stdin;
    public          postgres    false    220   �R       H          0    16590    drinktopping 
   TABLE DATA           :   COPY public.drinktopping (drinkid, toppingid) FROM stdin;
    public          postgres    false    227   �T       F          0    16580 	   itemorder 
   TABLE DATA           4   COPY public.itemorder (orderid, itemid) FROM stdin;
    public          postgres    false    225   �T       ?          0    16547    items 
   TABLE DATA           M   COPY public.items (itemid, drinkid, price, itemquantity, sizeid) FROM stdin;
    public          postgres    false    218   U       G          0    16585    itemtopping 
   TABLE DATA           8   COPY public.itemtopping (itemid, toppingid) FROM stdin;
    public          postgres    false    226   �U       =          0    16533    orders 
   TABLE DATA           l   COPY public.orders (orderid, userid, totalprice, address, phonenumber, note, status, orderdate) FROM stdin;
    public          postgres    false    216   �U       E          0    16572    sizes 
   TABLE DATA           A   COPY public.sizes (sizeid, namesize, price, drinkid) FROM stdin;
    public          postgres    false    224   �X       C          0    16563    toppings 
   TABLE DATA           A   COPY public.toppings (toppingid, nametopping, price) FROM stdin;
    public          postgres    false    222   MY       ;          0    16524    users 
   TABLE DATA           j   COPY public.users (userid, phonenumber, password, fullname, rolename, address, email, status) FROM stdin;
    public          postgres    false    214   Z       X           0    0    categories_categoryid_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('public.categories_categoryid_seq', 3, true);
          public          postgres    false    228            Y           0    0    drinks_drinkid_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.drinks_drinkid_seq', 11, true);
          public          postgres    false    219            Z           0    0    items_itemid_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.items_itemid_seq', 25, true);
          public          postgres    false    217            [           0    0    orders_orderid_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.orders_orderid_seq', 15, true);
          public          postgres    false    215            \           0    0    sizes_sizeid_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.sizes_sizeid_seq', 19, true);
          public          postgres    false    223            ]           0    0    toppings_toppingid_seq    SEQUENCE SET     E   SELECT pg_catalog.setval('public.toppings_toppingid_seq', 20, true);
          public          postgres    false    221            ^           0    0    users_userid_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.users_userid_seq', 15, true);
          public          postgres    false    213            �           2606    16680    categories categories_pkey 
   CONSTRAINT     `   ALTER TABLE ONLY public.categories
    ADD CONSTRAINT categories_pkey PRIMARY KEY (categoryid);
 D   ALTER TABLE ONLY public.categories DROP CONSTRAINT categories_pkey;
       public            postgres    false    229            �           2606    16561    drinks drinks_pkey 
   CONSTRAINT     U   ALTER TABLE ONLY public.drinks
    ADD CONSTRAINT drinks_pkey PRIMARY KEY (drinkid);
 <   ALTER TABLE ONLY public.drinks DROP CONSTRAINT drinks_pkey;
       public            postgres    false    220            �           2606    16594    drinktopping drinktopping_pkey 
   CONSTRAINT     l   ALTER TABLE ONLY public.drinktopping
    ADD CONSTRAINT drinktopping_pkey PRIMARY KEY (drinkid, toppingid);
 H   ALTER TABLE ONLY public.drinktopping DROP CONSTRAINT drinktopping_pkey;
       public            postgres    false    227    227            �           2606    16584    itemorder itemorder_pkey 
   CONSTRAINT     c   ALTER TABLE ONLY public.itemorder
    ADD CONSTRAINT itemorder_pkey PRIMARY KEY (orderid, itemid);
 B   ALTER TABLE ONLY public.itemorder DROP CONSTRAINT itemorder_pkey;
       public            postgres    false    225    225            �           2606    16552    items items_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.items
    ADD CONSTRAINT items_pkey PRIMARY KEY (itemid);
 :   ALTER TABLE ONLY public.items DROP CONSTRAINT items_pkey;
       public            postgres    false    218            �           2606    16589    itemtopping itemtopping_pkey 
   CONSTRAINT     i   ALTER TABLE ONLY public.itemtopping
    ADD CONSTRAINT itemtopping_pkey PRIMARY KEY (itemid, toppingid);
 F   ALTER TABLE ONLY public.itemtopping DROP CONSTRAINT itemtopping_pkey;
       public            postgres    false    226    226            �           2606    16540    orders orders_pkey 
   CONSTRAINT     U   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (orderid);
 <   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_pkey;
       public            postgres    false    216            �           2606    16579    sizes sizes_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.sizes
    ADD CONSTRAINT sizes_pkey PRIMARY KEY (sizeid);
 :   ALTER TABLE ONLY public.sizes DROP CONSTRAINT sizes_pkey;
       public            postgres    false    224            �           2606    16570    toppings toppings_pkey 
   CONSTRAINT     [   ALTER TABLE ONLY public.toppings
    ADD CONSTRAINT toppings_pkey PRIMARY KEY (toppingid);
 @   ALTER TABLE ONLY public.toppings DROP CONSTRAINT toppings_pkey;
       public            postgres    false    222            �           2606    16531    users users_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (userid);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    214            �           2606    16681    drinks drinks_categoryid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.drinks
    ADD CONSTRAINT drinks_categoryid_fkey FOREIGN KEY (categoryid) REFERENCES public.categories(categoryid) NOT VALID;
 G   ALTER TABLE ONLY public.drinks DROP CONSTRAINT drinks_categoryid_fkey;
       public          postgres    false    229    3236    220            �           2606    16620 &   drinktopping drinktopping_drinkid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.drinktopping
    ADD CONSTRAINT drinktopping_drinkid_fkey FOREIGN KEY (drinkid) REFERENCES public.drinks(drinkid) NOT VALID;
 P   ALTER TABLE ONLY public.drinktopping DROP CONSTRAINT drinktopping_drinkid_fkey;
       public          postgres    false    227    3224    220            �           2606    16625 (   drinktopping drinktopping_toppingid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.drinktopping
    ADD CONSTRAINT drinktopping_toppingid_fkey FOREIGN KEY (toppingid) REFERENCES public.toppings(toppingid) NOT VALID;
 R   ALTER TABLE ONLY public.drinktopping DROP CONSTRAINT drinktopping_toppingid_fkey;
       public          postgres    false    3226    222    227            �           2606    16605    itemorder itemorder_itemid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.itemorder
    ADD CONSTRAINT itemorder_itemid_fkey FOREIGN KEY (itemid) REFERENCES public.items(itemid) NOT VALID;
 I   ALTER TABLE ONLY public.itemorder DROP CONSTRAINT itemorder_itemid_fkey;
       public          postgres    false    3222    225    218            �           2606    16600     itemorder itemorder_orderid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.itemorder
    ADD CONSTRAINT itemorder_orderid_fkey FOREIGN KEY (orderid) REFERENCES public.orders(orderid) NOT VALID;
 J   ALTER TABLE ONLY public.itemorder DROP CONSTRAINT itemorder_orderid_fkey;
       public          postgres    false    3220    216    225            �           2606    16640    items items_drinkid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.items
    ADD CONSTRAINT items_drinkid_fkey FOREIGN KEY (drinkid) REFERENCES public.drinks(drinkid) NOT VALID;
 B   ALTER TABLE ONLY public.items DROP CONSTRAINT items_drinkid_fkey;
       public          postgres    false    218    220    3224            �           2606    16610 #   itemtopping itemtopping_itemid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.itemtopping
    ADD CONSTRAINT itemtopping_itemid_fkey FOREIGN KEY (itemid) REFERENCES public.items(itemid) NOT VALID;
 M   ALTER TABLE ONLY public.itemtopping DROP CONSTRAINT itemtopping_itemid_fkey;
       public          postgres    false    218    3222    226            �           2606    16615 &   itemtopping itemtopping_toppingid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.itemtopping
    ADD CONSTRAINT itemtopping_toppingid_fkey FOREIGN KEY (toppingid) REFERENCES public.toppings(toppingid) NOT VALID;
 P   ALTER TABLE ONLY public.itemtopping DROP CONSTRAINT itemtopping_toppingid_fkey;
       public          postgres    false    222    226    3226            �           2606    16541    orders orders_userid_fkey    FK CONSTRAINT     {   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_userid_fkey FOREIGN KEY (userid) REFERENCES public.users(userid);
 C   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_userid_fkey;
       public          postgres    false    3218    214    216            �           2606    16705    sizes sizes_drinkid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.sizes
    ADD CONSTRAINT sizes_drinkid_fkey FOREIGN KEY (drinkid) REFERENCES public.drinks(drinkid) NOT VALID;
 B   ALTER TABLE ONLY public.sizes DROP CONSTRAINT sizes_drinkid_fkey;
       public          postgres    false    3224    224    220            J   /   x�3����P(y�{"��sbZZ*�1gH��
�w�O����� ~�      A   �  x����n�0�g�)��E!�G6-g�=A�8[��Q�D
��-�LE�z�P�[ {t��Л�(9	��� P���}�NԻ,�B�nw�f������s��L�����5:eֆk�o� 5�Jmq[�Fdf�QL"�@��� 1A֊��=JP�J����v?E�]��I)=�3o.��%�t)��e��AYT+�*����|�	éX�J.�V,3pB>������ʕ~fa~�-V��G���?j4��Ջ%��eXɬN������-�#�G,q�儍)���A2L	f\+�h@9�1��hL�	��ؽ�7:�Y�q�˳ny�j�(�1?
���1�BZ-*Gyut��+(1E?r>�#�n
;��_��)!U	�b�B}�9x��d��AbO�*aAz������=�S	�@]���)&1��Z��Ѭ�}��b���O���ޠ��{-�+e��C
�r����%�r]�׽V���С=�'f?�����Y      H   "   x�3�4�2�4bc.sNCa
$��b���� C�      F   >   x���� �����!����Go�����a���2���&���LW0CI��TF=�=�Q��      ?   g   x�U���@C�q1(�`{��� ����'d�h�n2�J��p�xs�6L�����rg� �Ęa�׳�:��gJj7KP���J/��X/;\��W��� �      G   9   x�%��	  �s3��T����s���A>dd�$8�G��mNL�<T���s#���H
      =   �  x����jQ��w��<@:�����4�m��r3֐��SAw"�JPą�B#�(�u��Ք�Ǽ���XM��ì�N����}������$����u�B
'O��Eց~u[u�2g\:�^+��R��AV#�[�����|�ÝjV�Xo���x8�d�Qnpz4p�p�sg���cB�����i�,���E���q]����f��jށi���i]>����Q�����;jmX�d
'ϪY�p߃�S�ӘmO���$'7�.e�b��)���&Z��pc��F*d׷���8�;<{� a�.b�������m��W�w�s򰀝���߻dܻХ>@\.�i�����e䉤�Tl�h"�2�yC!Pv����K�5�^Ѵ�ke��N�_	=�,�SW�]��^Z���%Ņ����2�[��-��r����9���l�Ev�4�U7Ҕ��T[+��]+aP}.�W����2��\;��
�b�|3q��a�h�p�JFF0�����ipm|N|Ȧ(����x㤍�����w�${}%�S�+kd��-r��K�%��,��s�p����-'��t��)mCG�S�k,��:�¨��"H<��������Oږ��z��p7\45T	��	��D�t՝Ͷ�������%�;��sgR�`0��o
�/��r�|��Ī׼&Uf�[�#���~w�I�pm���1�6�*6)t���]���{u��jNr��x1[1.�O��~}ѪA#4����g����Q}Xn;�      E   f   x�3���x���������ӈ˔3���Չ���
ߘ˜�����y�&P�!L?�o�eU1ϐ���*oh�`V`�e�bP �s.C�P�=... ��2i      C   �   x�3�	:����q�)T!$��u~\F�ޮ�@	��`W��1g���]�=��^��w�	����}�
?w�c���34 I�q�d<ܵ09C!;#?1S!��<�6SۏLp���[�-
�8<E���"nh�yd��]kK�L|��*h���p����Ē�D��8��^�R�k{2D0F��� �R/      ;   +  x����n�F�k�)X�(^E��.�.�(S�.&ҌH�CRѼ����l�:�n�E���*i�{�M2�e�a�X۰� �|�w�C�,I+7�8gW�{.�m�B��-5��m�hs���C�F�jf�zW��W�b���N3@hnvs������/�l"Hd�2S#��燿s����~�r���\�W���KX����ħ��o����Ȼ���_�pq� rC�m(k�J��9c��D�n��b��݋Q|�\�K�7���*;�-E�E-}z[���õ�*�:� #*Ԫ�;���� v�!�a���� �8)���3��qe^h���X��Ѵ`uG�RT��W���2EY�I����ͼE4م������!���(?�G�9t�����}�����"c�)O ��47��t0�NG1f./}h#?���dD�z3[������i�����K���?�2͜���8�9�������6��s�]�zߢ�
׽���ts��F-d�=�U�(F|���%C|	Iz���H�#rz>�`��c�Z�>*�Dc�U� z�)�X}���3��t.��S�#F�]o��B	#xկ�ಝ��f�k)�l?6�`6�u<�W��8F��;^�F�@�����;�| /�z����C�79�.�ɾ�	<+>2wu5Vb+�Z%kR������C��l��:��,�n�4?��1�N<<k�c^<��x4�:�L�x{�
s<����d��-��d����\Ҝ�1��X���x�4v�fk���׽ŷn?���FZ���{���g����?a4&�     